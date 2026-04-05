// doomgeneric for Allegro library

#include "doomkeys.h"
#include "i_system.h"
#include "i_video.h"
#include "m_argv.h"
#include "doomgeneric.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>

#define ALLEGRO_NO_KEY_DEFINES 1
#include <allegro.h>
#undef uint32_t // ugly hack because Allegro is Old and doesn't know modern GCC has stdint.h


static bool videomode_set = false;

static BITMAP *temp_bitmap = NULL;

static PALETTE pal;

#define KEYQUEUE_SIZE 16

static volatile unsigned int s_KeyQueue[KEYQUEUE_SIZE];
static volatile unsigned int s_KeyQueueWriteIndex = 0;
static unsigned int s_KeyQueueReadIndex = 0;

static volatile unsigned int s_ticks = 0;


void key_callback(int scancode) {
	// this is in interrupt context, avoid heavy processing and be careful about volatile writes
	s_KeyQueue[s_KeyQueueWriteIndex] = scancode;
	s_KeyQueueWriteIndex = (s_KeyQueueWriteIndex + 1) % KEYQUEUE_SIZE;
}
END_OF_FUNCTION(key_callback);


void timer_callback(void) {
	// also in interrupt context
	s_ticks++;
}
END_OF_FUNCTION(timer_callback);


void DG_Init() {
	int result;

	printf("Initializing Allegro\n");

	result = allegro_init();
	if (result != 0)
	{
		I_Error("Allegro init failed: %d %s\n", result, allegro_error);
	}

	I_AtExit(allegro_exit, true);

	LOCK_FUNCTION(key_callback);
	LOCK_VARIABLE(s_KeyQueue);
	LOCK_VARIABLE(s_KeyQueueWriteIndex);
	LOCK_VARIABLE(s_KeyQueueReadIndex);

	LOCK_FUNCTION(timer_callback);
	LOCK_VARIABLE(s_ticks);

	install_keyboard();
	keyboard_lowlevel_callback = key_callback;

	install_timer();
	result = install_int(timer_callback, 1);
	if (result < 0) {
		I_Error("Unable to install timer: %d %s\n", result, allegro_error);
	}

	// don't set video mode yet so initialization messages stay on screen
}


static void back_to_text_mode(void) {
	set_gfx_mode(GFX_TEXT, 80, 25, 0, 0);
}


void DG_DrawFrame()
{
	if (!DG_ScreenBuffer) {
		return;
	}

	if (!videomode_set) {
		int y;
		int result;

#ifdef CMAP256
		set_color_depth(8);
#else  // CMAP256
		// does not seem to work on real DOS hardware
		set_color_depth(32);
#endif  // CMAP256

		result = set_gfx_mode(GFX_AUTODETECT_FULLSCREEN, DOOMGENERIC_RESX, DOOMGENERIC_RESY, 0, 0);
		if (result < 0) {
			I_Error("Failed to set video mode: %s\n", allegro_error);
		}

		// register an exit handler to return to text mode
		// while this is also done by allegro_exit handler registered earlier
		// that's too late for ENDOOM screen to work correctly
		I_AtExit(back_to_text_mode, true);

		if (!screen) {
			I_Error("screen is null\n");
		}

		temp_bitmap = create_bitmap(DOOMGENERIC_RESX, DOOMGENERIC_RESY);
		if (!temp_bitmap) {
			I_Error("Failed to create temp bitmap\n");
		}

		// this is an evil hack
		// replace the internal line pointers with pointers into DG_ScreenBuffer
		// this avoids some copying
		// it might crash when freeing the bitmap but we never do
		for (y = 0; y < DOOMGENERIC_RESY; y++) {
			temp_bitmap->line[y] = (unsigned char *) &DG_ScreenBuffer[y * DOOMGENERIC_RESX];
		}

		clear_bitmap(temp_bitmap);

		videomode_set = true;
		palette_changed = true;
	}

#ifdef CMAP256

	// changing palette implicitly waits for vsync
	// TODO: should do it explicitly in case where we don't change palette
	if (palette_changed) {
		int i;

		for (i = 0; i < 256; i++) {
			// allegro uses VGA range 0..63
			pal[i].r = colors[i].r >> 2;
			pal[i].g = colors[i].g >> 2;
			pal[i].b = colors[i].b >> 2;
		}
		set_palette(pal);

		palette_changed = false;
	}

#endif  // CMAP256

	blit(temp_bitmap, screen, 0, 0, 0, 0, DOOMGENERIC_RESX, DOOMGENERIC_RESY);
}


void DG_SleepMs(uint32_t ms)
{
	rest(ms);
}


uint32_t DG_GetTicksMs()
{
	return s_ticks;
}


int DG_GetKey(int *pressed, unsigned char *doomKey)
{
	if (s_KeyQueueReadIndex == s_KeyQueueWriteIndex){
		//key queue is empty
		return 0;
	} else {
		bool released;
		short keyData = 0;
		int scancode = s_KeyQueue[s_KeyQueueReadIndex];
		s_KeyQueueReadIndex++;
		s_KeyQueueReadIndex %= KEYQUEUE_SIZE;

		released = scancode & 0x80;
		*pressed = !released;

		scancode = scancode & 0x7F;

		switch (scancode) {
		case  __allegro_KEY_RIGHT:
			keyData = KEY_RIGHTARROW;
			break;

		case  __allegro_KEY_LEFT:
			keyData = KEY_LEFTARROW;
			break;

		case  __allegro_KEY_UP:
			keyData = KEY_UPARROW;
			break;

		case  __allegro_KEY_DOWN:
			keyData = KEY_DOWNARROW;
			break;

		case  __allegro_KEY_COMMA:
			keyData = KEY_STRAFE_L;
			break;

		case  __allegro_KEY_STOP:
			keyData = KEY_STRAFE_R;
			break;

		case  __allegro_KEY_SPACE:
			keyData = KEY_USE;
			break;

		case  __allegro_KEY_LCONTROL:
			keyData = KEY_FIRE;
			break;

		case  __allegro_KEY_ESC:
			keyData = KEY_ESCAPE;
			break;

		case  __allegro_KEY_ENTER:
			keyData = KEY_ENTER;
			break;

		case  __allegro_KEY_TAB:
			keyData = KEY_TAB;
			break;

		case  __allegro_KEY_F1:
			keyData = KEY_F1;
			break;

		case  __allegro_KEY_F2:
			keyData = KEY_F2;
			break;

		case  __allegro_KEY_F3:
			keyData = KEY_F3;
			break;

		case  __allegro_KEY_F4:
			keyData = KEY_F4;
			break;

		case  __allegro_KEY_F5:
			keyData = KEY_F5;
			break;

		case  __allegro_KEY_F6:
			keyData = KEY_F6;
			break;

		case  __allegro_KEY_F7:
			keyData = KEY_F7;
			break;

		case  __allegro_KEY_F8:
			keyData = KEY_F8;
			break;

		case  __allegro_KEY_F9:
			keyData = KEY_F9;
			break;

		case  __allegro_KEY_F10:
			keyData = KEY_F10;
			break;

		case  __allegro_KEY_F11:
			keyData = KEY_F11;
			break;

		case  __allegro_KEY_F12:
			keyData = KEY_F12;
			break;

		case  __allegro_KEY_BACKSPACE:
			keyData = KEY_BACKSPACE;
			break;

		case  __allegro_KEY_PAUSE:
			keyData = KEY_PAUSE;
			break;

		case  __allegro_KEY_EQUALS:
			keyData = KEY_EQUALS;
			break;

		case  __allegro_KEY_MINUS:
			keyData = KEY_MINUS;
			break;

		case  __allegro_KEY_LSHIFT:
		case  __allegro_KEY_RSHIFT:
			keyData = KEY_RSHIFT;
			break;

		case  __allegro_KEY_RCONTROL:
			keyData = KEY_RCTRL;
			break;

		case  __allegro_KEY_ALT:
			keyData = KEY_RALT;
			break;

		case  __allegro_KEY_CAPSLOCK:
			keyData = KEY_CAPSLOCK;
			break;

		case  __allegro_KEY_NUMLOCK:
			keyData = KEY_NUMLOCK;
			break;

		case  __allegro_KEY_SCRLOCK:
			keyData = KEY_SCRLCK;
			break;

		case  __allegro_KEY_PRTSCR:
			keyData = KEY_PRTSCR;
			break;

		case  __allegro_KEY_HOME:
			keyData = KEY_HOME;
			break;

		case  __allegro_KEY_END:
			keyData = KEY_END;
			break;

		case  __allegro_KEY_PGUP:
			keyData = KEY_PGUP;
			break;

		case  __allegro_KEY_PGDN:
			keyData = KEY_PGDN;
			break;

		case  __allegro_KEY_INSERT:
			keyData = KEY_INS;
			break;

		case  __allegro_KEY_DEL:
			keyData = KEY_DEL;
			break;

		case  __allegro_KEY_0_PAD:
			keyData = KEYP_0;
			break;

		case  __allegro_KEY_1_PAD:
			keyData = KEYP_1;
			break;

		case  __allegro_KEY_2_PAD:
			keyData = KEYP_2;
			break;

		case  __allegro_KEY_3_PAD:
			keyData = KEYP_3;
			break;

		case  __allegro_KEY_4_PAD:
			keyData = KEYP_4;
			break;

		case  __allegro_KEY_5_PAD:
			keyData = KEYP_5;
			break;

		case  __allegro_KEY_6_PAD:
			keyData = KEYP_6;
			break;

		case  __allegro_KEY_7_PAD:
			keyData = KEYP_7;
			break;

		case  __allegro_KEY_8_PAD:
			keyData = KEYP_8;
			break;

		case  __allegro_KEY_9_PAD:
			keyData = KEYP_9;
			break;

		case  __allegro_KEY_SLASH_PAD:
			keyData = KEYP_DIVIDE;
			break;

		case  __allegro_KEY_PLUS_PAD:
			keyData = KEYP_PLUS;
			break;

		case  __allegro_KEY_MINUS_PAD:
			keyData = KEYP_MINUS;
			break;

		case  __allegro_KEY_ASTERISK:
			keyData = KEYP_MULTIPLY;
			break;

		case  __allegro_KEY_DEL_PAD:
			keyData = KEYP_PERIOD;
			break;

		case  __allegro_KEY_EQUALS_PAD:
			keyData = KEYP_EQUALS;
			break;

		case  __allegro_KEY_ENTER_PAD:
			keyData = KEYP_ENTER;
			break;

		default:
			keyData = scancode_to_ascii(scancode);
			break;
		}

		if (keyData != 0) {
			*doomKey = keyData & 0xFF;
		}

		return 1;
	}

	return 0;
}


void DG_SetWindowTitle(const char *title)
{
	set_window_title(title);
}


int main(int argc, char **argv)
{
	doomgeneric_Create(argc, argv);

	while (true)
	{
		doomgeneric_Tick();
	}

	return 0;
}
