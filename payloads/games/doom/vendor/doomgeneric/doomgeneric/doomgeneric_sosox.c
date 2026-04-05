//doomgeneric for soso os (nano-x version)

#include "doomkeys.h"
#include "m_argv.h"
#include "doomgeneric.h"

#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <sys/time.h>
#include <sys/ioctl.h>

#include <termios.h>

#include "nano-X.h"


#define KEYQUEUE_SIZE 16

static unsigned short g_key_queue[KEYQUEUE_SIZE];
static unsigned int g_key_queue_write_index = 0;
static unsigned int g_key_queue_read_index = 0;

static unsigned char g_key_states[256];


static GR_WINDOW_ID  wid;
static GR_GC_ID      gc;
static unsigned char* windowBuffer = 0;
static const int winSizeX = DOOMGENERIC_RESX;
static const int winSizeY = DOOMGENERIC_RESY;


static void add_key_to_queue(int pressed, unsigned char key)
{
    unsigned short key_data = (pressed << 8) | key;

    g_key_queue[g_key_queue_write_index] = key_data;
    g_key_queue_write_index++;
    g_key_queue_write_index %= KEYQUEUE_SIZE;
}

struct termios orig_termios;

void disable_raw_mode()
{
  tcsetattr(STDIN_FILENO, TCSAFLUSH, &orig_termios);
}

void enable_raw_mode()
{
  tcgetattr(STDIN_FILENO, &orig_termios);
  atexit(disable_raw_mode);
  struct termios raw = orig_termios;
  raw.c_lflag &= ~(ECHO);
  raw.c_cc[VMIN] = 0;
  tcsetattr(STDIN_FILENO, TCSAFLUSH, &raw);
}

void DG_Init()
{
    if (GrOpen() < 0)
    {
        GrError("GrOpen failed");
        return;
    }

    gc = GrNewGC();
    GrSetGCUseBackground(gc, GR_FALSE);
    GrSetGCForeground(gc, MWRGB( 255, 0, 0 ));

    wid = GrNewBufferedWindow(GR_WM_PROPS_APPFRAME |
                        GR_WM_PROPS_CAPTION  |
                        GR_WM_PROPS_CLOSEBOX |
                        GR_WM_PROPS_BUFFER_MMAP |
                        GR_WM_PROPS_BUFFER_BGRA,
                        "Doom",
                        GR_ROOT_WINDOW_ID, 
                        50, 50, winSizeX, winSizeY, MWRGB( 255, 255, 255 ));

    GrSelectEvents(wid, GR_EVENT_MASK_EXPOSURE | 
                        GR_EVENT_MASK_KEY_UP |
                        GR_EVENT_MASK_KEY_DOWN |
                        GR_EVENT_MASK_TIMER |
                        GR_EVENT_MASK_CLOSE_REQ);

    GrMapWindow (wid);

    windowBuffer = GrOpenClientFramebuffer(wid);

    enable_raw_mode();
}

static unsigned char convert_to_doom_keyx(int wkey)
{
    unsigned char doomkey = 0;

    switch (wkey)
	{
	case MWKEY_ENTER:   doomkey = KEY_ENTER; break;
	case MWKEY_ESCAPE:   doomkey = KEY_ESCAPE; break;
	case MWKEY_TAB:      doomkey = KEY_TAB; break;
	case MWKEY_DOWN: case MWKEY_KP2:     doomkey = KEY_DOWNARROW; break;
	case MWKEY_UP: case MWKEY_KP8:      doomkey = KEY_UPARROW; break;
	case MWKEY_LEFT: case MWKEY_KP4:    doomkey = KEY_LEFTARROW; break;
	case MWKEY_RIGHT: case MWKEY_KP6:   doomkey = KEY_RIGHTARROW; break;
    case MWKEY_LCTRL: case MWKEY_RCTRL:    doomkey = KEY_FIRE; break;
    case MWKEY_LSHIFT: case MWKEY_RSHIFT:    doomkey = KEY_RSHIFT; break;
    case ' ':    doomkey = KEY_USE; break;
	case MWKEY_F1:  doomkey = KEY_F1; break;
	case MWKEY_F2:  doomkey = KEY_F2; break;
	case MWKEY_F3:  doomkey = KEY_F3; break;
	case MWKEY_F4:  doomkey = KEY_F4; break;
	case MWKEY_F5:  doomkey = KEY_F5; break;
	case MWKEY_F6:  doomkey = KEY_F6; break;
	case MWKEY_F7:  doomkey = KEY_F7; break;
	case MWKEY_F8:  doomkey = KEY_F8; break;
	case MWKEY_F9:  doomkey = KEY_F9; break;
	case MWKEY_F10: doomkey = KEY_F10; break;
	case MWKEY_F11: doomkey = KEY_F11; break;
	case MWKEY_F12: doomkey = KEY_F12; break;
	
	default:
		break;
	}

    if ((wkey >= 'a' && wkey <= 'z') ||
        (wkey >= 'A' && wkey <= 'Z') ||
        (wkey >= '0' && wkey <= '9'))
    {
        doomkey = (uint8_t)wkey;
    }

    return doomkey;
}

void DG_DrawFrame()
{
    GR_EVENT event;
    GR_EVENT_KEYSTROKE *kp = NULL;

    unsigned char key = 0;

    while (GrPeekEvent(&event))
    {
        GrGetNextEvent(&event);

        switch (event.type)
        {
        case GR_EVENT_TYPE_CLOSE_REQ:
            GrClose();
            exit (0);
            break;
        case GR_EVENT_TYPE_EXPOSURE:
            break;
        case GR_EVENT_TYPE_KEY_UP:
            kp = (GR_EVENT_KEYSTROKE*)&event;
            key = convert_to_doom_keyx(kp->ch);
            if (key > 0 && key < sizeof(g_key_states))
            {
                unsigned char state = g_key_states[key];
                if (state == 1)
                {
                    g_key_states[key] = 0;
                    add_key_to_queue(0, key);
                }
            }
            break;
        case GR_EVENT_TYPE_KEY_DOWN:
            //this event comes continuously while pressed, so checking for changes only!
            kp = (GR_EVENT_KEYSTROKE*)&event;
            key = convert_to_doom_keyx(kp->ch);
            if (key > 0 && key < sizeof(g_key_states))
            {
                unsigned char state = g_key_states[key];
                if (state == 0)
                {
                    g_key_states[key] = 1;
                    add_key_to_queue(1, key);
                }
            }
            break;
        case GR_EVENT_TYPE_TIMER:
            
            break;
        }
    }

    memcpy(windowBuffer, DG_ScreenBuffer, DOOMGENERIC_RESX * DOOMGENERIC_RESY * 4);

    GrFlushWindow(wid);
}

void DG_SleepMs(uint32_t ms)
{
    usleep(ms * 1000);
}

uint32_t DG_GetTicksMs()
{
    struct timeval  tp;
    struct timezone tzp;

    gettimeofday(&tp, &tzp);

    return (tp.tv_sec * 1000) + (tp.tv_usec / 1000); /* return milliseconds */
}

int DG_GetKey(int* pressed, unsigned char* doomKey)
{
    if (g_key_queue_read_index == g_key_queue_write_index)
    {
        //key queue is empty

        return 0;
    }
    else
    {
        unsigned short keyData = g_key_queue[g_key_queue_read_index];
        g_key_queue_read_index++;
        g_key_queue_read_index %= KEYQUEUE_SIZE;

        *pressed = keyData >> 8;
        *doomKey = keyData & 0xFF;

        return 1;
    }
}

void DG_SetWindowTitle(const char * title)
{
    GrSetWindowTitle(wid, title);
}

int main(int argc, char **argv)
{
    memset(g_key_states, 0, sizeof(g_key_states));

    doomgeneric_Create(argc, argv);

    for (int i = 0; ; i++)
    {
        doomgeneric_Tick();
    }
    
    return 0;
}