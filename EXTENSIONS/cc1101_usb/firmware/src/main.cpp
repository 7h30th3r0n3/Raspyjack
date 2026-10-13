/*
 * RaspyJack CC1101-over-USB bridge  —  ESP32-S3 firmware
 *
 * Exposes a TI CC1101 (wired on SPI) to the Raspberry Pi over USB-CDC, so the
 * RaspyJack sub-GHz payloads work on any Pi without consuming its SPI/GPIO.
 *
 * Protocol: COBS-framed, see EXTENSIONS/cc1101_usb/PROTOCOL.md  (PROTO_VER 1).
 * Host side: payloads/_cc1101_usb.py.
 *
 * Timing-critical work is done here: SPI_XFER is a transparent passthrough
 * (so the whole Python register layer runs unchanged), while TX_RAW replays
 * OOK waveforms by bit-banging GDO0 and RX_RAW timestamps GDO0 edges.
 */

#include <Arduino.h>
#include <SPI.h>

// ---- Pin map (overridable from platformio.ini build_flags) ----
#ifndef PIN_SCK
#define PIN_SCK 12
#endif
#ifndef PIN_MISO
#define PIN_MISO 13
#endif
#ifndef PIN_MOSI
#define PIN_MOSI 11
#endif
#ifndef PIN_CS
#define PIN_CS 10
#endif
#ifndef PIN_GDO0
#define PIN_GDO0 4
#endif
#ifndef PIN_GDO2
#define PIN_GDO2 5
#endif
#ifndef PIN_RF_SW
#define PIN_RF_SW -1
#endif

static const int pinRfSw = PIN_RF_SW;

// ---- Protocol constants ----
#define PROTO_VER 1
#define FW_MAJOR 0
#define FW_MINOR 1
#define MAX_BODY 2048

enum {
  CMD_PING = 0x01, CMD_INFO = 0x02,
  CMD_SPI_XFER = 0x10, CMD_RF_SWITCH = 0x11, CMD_POWER = 0x12, CMD_GDO_READ = 0x13,
  CMD_TX_RAW = 0x20, CMD_RX_RAW = 0x21,
};
enum {
  ST_OK = 0x00, ST_BADCMD = 0x01, ST_BADLEN = 0x02, ST_BUSY = 0x03,
  ST_NOCHIP = 0x04, ST_CAPERR = 0x05,
};

// ---- CC1101 ----
#define SRES 0x30
#define STX 0x35
#define SIDLE 0x36
#define SFTX 0x3B
#define REG_IOCFG0 0x02
#define REG_PKTCTRL0 0x08
#define REG_MDMCFG2 0x12
#define REG_FREND0 0x22
#define REG_VERSION 0x31
#define REG_PARTNUM 0x30
#define PA_TABLE 0x3E

static SPISettings ccSpi(1000000, MSBFIRST, SPI_MODE0);

// ---- edge-capture ISR state ----
static volatile uint32_t isrLastEdge = 0;
static volatile int16_t  isrBuf[1024];
static volatile uint16_t isrN = 0;
static volatile uint16_t isrMax = 0;

static void IRAM_ATTR gdoISR() {
  uint32_t now = micros();
  uint32_t d = now - isrLastEdge;
  isrLastEdge = now;
  // Pin level AFTER the edge; the elapsed time belongs to the previous level.
  int lvl = digitalRead(PIN_GDO0);
  if (isrN < isrMax && d > 50 && d < 200000) {
    // previous level = !lvl : high before a falling edge, low before a rising
    isrBuf[isrN++] = (lvl == LOW) ? (int16_t)d : (int16_t)(-(int32_t)d);
  }
}

// ======================= COBS =======================
static size_t cobsEncode(const uint8_t *in, size_t len, uint8_t *out) {
  size_t oi = 1, codeIdx = 0;
  uint8_t code = 1;
  for (size_t i = 0; i < len; i++) {
    if (in[i] == 0) { out[codeIdx] = code; codeIdx = oi++; code = 1; }
    else {
      out[oi++] = in[i];
      if (++code == 0xFF) { out[codeIdx] = code; codeIdx = oi++; code = 1; }
    }
  }
  out[codeIdx] = code;
  return oi;
}
static size_t cobsDecode(const uint8_t *in, size_t len, uint8_t *out) {
  size_t i = 0, oi = 0;
  while (i < len) {
    uint8_t code = in[i];
    if (code == 0) return 0;
    i++;
    for (uint8_t j = 1; j < code && i < len; j++) out[oi++] = in[i++];
    if (code != 0xFF && i < len) out[oi++] = 0;
  }
  return oi;
}

// ======================= CC1101 SPI helpers =======================
static inline void csLow()  { digitalWrite(PIN_CS, LOW); }
static inline void csHigh() { digitalWrite(PIN_CS, HIGH); }

static bool waitReady() {
  // After CS low the CC1101 pulls SO (MISO) low when ready (CHIP_RDYn).
  uint32_t t0 = micros();
  while (digitalRead(PIN_MISO) == HIGH) {
    if (micros() - t0 > 2000) return false;
  }
  return true;
}

// Full-duplex transfer of n bytes; miso written in place over a copy.
static void ccXfer(const uint8_t *mosi, uint8_t *miso, size_t n) {
  SPI.beginTransaction(ccSpi);
  csLow();
  waitReady();
  for (size_t i = 0; i < n; i++) miso[i] = SPI.transfer(mosi[i]);
  csHigh();
  SPI.endTransaction();
}
static uint8_t ccStrobe(uint8_t s) { uint8_t r; ccXfer(&s, &r, 1); return r; }
static void ccWrite(uint8_t a, uint8_t v) { uint8_t o[2] = {a, v}, in[2]; ccXfer(o, in, 2); }
static uint8_t ccRead(uint8_t a) { uint8_t o[2] = {(uint8_t)(a | 0x80), 0}, in[2]; ccXfer(o, in, 2); return in[1]; }
static uint8_t ccStatus(uint8_t a) { uint8_t o[2] = {(uint8_t)(a | 0xC0), 0}, in[2]; ccXfer(o, in, 2); return in[1]; }
static void ccBurst(uint8_t a, const uint8_t *d, size_t n) {
  uint8_t o[70], in[70];
  if (n > 68) n = 68;
  o[0] = a | 0x40;
  for (size_t i = 0; i < n; i++) o[i + 1] = d[i];
  ccXfer(o, in, n + 1);
}

// ======================= Frame TX =======================
static uint8_t frameBody[MAX_BODY];
static uint8_t frameOut[MAX_BODY + MAX_BODY / 254 + 4];

static void sendResponse(uint8_t status, const uint8_t *data, size_t n) {
  static uint8_t body[MAX_BODY];
  if (n > MAX_BODY - 1) n = MAX_BODY - 1;
  body[0] = status;
  for (size_t i = 0; i < n; i++) body[i + 1] = data[i];
  size_t enc = cobsEncode(body, n + 1, frameOut);
  Serial.write(frameOut, enc);
  Serial.write((uint8_t)0x00);
  Serial.flush();
}
static void sendOk() { sendResponse(ST_OK, nullptr, 0); }
static void sendErr(uint8_t code) { sendResponse(code, nullptr, 0); }

// ======================= Command handlers =======================
static void doTxRaw(const uint8_t *a, size_t n) {
  if (n < 4) { sendErr(ST_BADLEN); return; }
  uint8_t repeat = a[0];
  uint8_t flags = a[1];
  uint16_t cnt = a[2] | (a[3] << 8);
  if (repeat < 1) repeat = 1;
  if (4 + (size_t)cnt * 2 > n) { sendErr(ST_BADLEN); return; }
  const uint8_t *p = a + 4;

  // Save + configure CC1101 for asynchronous-serial OOK.
  uint8_t sIocfg0 = ccRead(REG_IOCFG0);
  uint8_t sMdm2 = ccRead(REG_MDMCFG2);
  uint8_t sPkt = ccRead(REG_PKTCTRL0);
  uint8_t sFrend0 = ccRead(REG_FREND0);
  ccWrite(REG_IOCFG0, 0x2E);     // GDO0 -> Hi-Z, the ESP32 drives it
  ccWrite(REG_MDMCFG2, 0x30);    // OOK/ASK, no preamble/sync
  ccWrite(REG_PKTCTRL0, 0x32);   // async serial, infinite length
  ccWrite(REG_FREND0, 0x11);     // PA_POWER index 1
  uint8_t pa[2] = {0x00, 0xC0};
  ccBurst(PA_TABLE, pa, 2);

  pinMode(PIN_GDO0, OUTPUT);
  digitalWrite(PIN_GDO0, LOW);
  ccStrobe(SIDLE);
  ccStrobe(STX);
  delayMicroseconds(1000);

  for (uint8_t r = 0; r < repeat; r++) {
    for (uint16_t i = 0; i < cnt; i++) {
      int16_t dur = (int16_t)(p[i * 2] | (p[i * 2 + 1] << 8));
      digitalWrite(PIN_GDO0, dur > 0 ? HIGH : LOW);
      uint32_t us = dur >= 0 ? (uint32_t)dur : (uint32_t)(-(int32_t)dur);
      if (us) delayMicroseconds(us);
    }
    digitalWrite(PIN_GDO0, LOW);
    if ((flags & 0x01) && r + 1 < repeat) delayMicroseconds(1000);
  }
  digitalWrite(PIN_GDO0, LOW);

  // Restore.
  ccStrobe(SIDLE);
  ccWrite(REG_IOCFG0, sIocfg0);
  ccWrite(REG_MDMCFG2, sMdm2);
  ccWrite(REG_PKTCTRL0, sPkt);
  ccWrite(REG_FREND0, sFrend0);
  pinMode(PIN_GDO0, INPUT);
  sendOk();
}

static void doRxRaw(const uint8_t *a, size_t n) {
  if (n < 7) { sendErr(ST_BADLEN); return; }
  uint16_t durMs = a[0] | (a[1] << 8);
  uint32_t idleUs = (uint32_t)(a[2] | (a[3] << 8));
  uint16_t maxSym = a[4] | (a[5] << 8);
  if (maxSym == 0 || maxSym > 1000) maxSym = 1000;  // keep response <= MAX_BODY
  // Host has already put the CC1101 in async-serial RX (IOCFG0=0x0D) via SPI.

  pinMode(PIN_GDO0, INPUT);
  isrN = 0;
  isrMax = maxSym;
  isrLastEdge = micros();
  attachInterrupt(digitalPinToInterrupt(PIN_GDO0), gdoISR, CHANGE);

  uint32_t start = millis();
  while (millis() - start < durMs) {
    if (isrN >= isrMax) break;
    if (isrN > 0 && (micros() - isrLastEdge) > idleUs) break;
    delay(1);
  }
  detachInterrupt(digitalPinToInterrupt(PIN_GDO0));

  uint16_t cnt = isrN;
  static uint8_t out[2 + 1024 * 2];
  out[0] = cnt & 0xFF;
  out[1] = (cnt >> 8) & 0xFF;
  for (uint16_t i = 0; i < cnt; i++) {
    out[2 + i * 2] = isrBuf[i] & 0xFF;
    out[2 + i * 2 + 1] = (isrBuf[i] >> 8) & 0xFF;
  }
  sendResponse(ST_OK, out, 2 + (size_t)cnt * 2);
}

static void dispatch(const uint8_t *body, size_t len) {
  if (len < 1) { sendErr(ST_BADLEN); return; }
  uint8_t cmd = body[0];
  const uint8_t *a = body + 1;
  size_t n = len - 1;

  switch (cmd) {
    case CMD_PING: {
      uint8_t d[7] = {'R', 'J', 'C', '1', PROTO_VER, FW_MAJOR, FW_MINOR};
      sendResponse(ST_OK, d, 7);
      break;
    }
    case CMD_INFO: {
      uint8_t d[4] = {ccStatus(REG_VERSION), ccStatus(REG_PARTNUM),
                      PIN_GDO0, PIN_GDO2};
      sendResponse(ST_OK, d, 4);
      break;
    }
    case CMD_SPI_XFER: {
      if (n == 0 || n > 70) { sendErr(ST_BADLEN); return; }
      static uint8_t miso[70];
      ccXfer(a, miso, n);
      sendResponse(ST_OK, miso, n);
      break;
    }
    case CMD_RF_SWITCH: {
      if (n < 1) { sendErr(ST_BADLEN); return; }
      if (pinRfSw >= 0) { pinMode(pinRfSw, OUTPUT); digitalWrite(pinRfSw, a[0] ? HIGH : LOW); }
      sendOk();
      break;
    }
    case CMD_POWER:
      sendOk();  // CC1101 is powered from the ESP32 3V3 rail; nothing to gate.
      break;
    case CMD_GDO_READ: {
      int pin = (n >= 1 && a[0] == 2) ? PIN_GDO2 : PIN_GDO0;
      pinMode(pin, INPUT);
      uint8_t lvl = digitalRead(pin) ? 1 : 0;
      sendResponse(ST_OK, &lvl, 1);
      break;
    }
    case CMD_TX_RAW: doTxRaw(a, n); break;
    case CMD_RX_RAW: doRxRaw(a, n); break;
    default: sendErr(ST_BADCMD); break;
  }
}

// ======================= Arduino =======================
static uint8_t rxFrame[MAX_BODY + 16];
static size_t rxLen = 0;

void setup() {
  Serial.begin(115200);
  pinMode(PIN_CS, OUTPUT);
  csHigh();
  pinMode(PIN_GDO0, INPUT);
  pinMode(PIN_GDO2, INPUT);
  if (pinRfSw >= 0) pinMode(pinRfSw, OUTPUT);
  SPI.begin(PIN_SCK, PIN_MISO, PIN_MOSI, PIN_CS);

  // Reset the CC1101.
  ccStrobe(SRES);
  delay(10);
}

void loop() {
  while (Serial.available()) {
    uint8_t b = (uint8_t)Serial.read();
    if (b == 0x00) {
      if (rxLen > 0) {
        size_t dl = cobsDecode(rxFrame, rxLen, frameBody);
        if (dl > 0) dispatch(frameBody, dl);
      }
      rxLen = 0;
    } else if (rxLen < sizeof(rxFrame)) {
      rxFrame[rxLen++] = b;
    } else {
      rxLen = 0;  // overrun -> resync on next delimiter
    }
  }
}
