#!/bin/bash

# ===================================================================
# Raspyjack Payload Showcase
# -------------------------------------------------------------------
# This payload demonstrates the full capabilities of the dashboard UI,
# testing SERIAL_WRITE and the various LED command syntaxes.
# ===================================================================

# --- Section 1: Testing STATE commands ---
# These commands use predefined color and pattern combinations.

SERIAL_WRITE "Testing STATE commands..."
sleep 2

BUTTON 5s

SERIAL_WRITE "--> LED SETUP"
LED SETUP
sleep 4

SERIAL_WRITE "--> LED ATTACK"
LED ATTACK
sleep 4

SERIAL_WRITE "--> LED STAGE3"
LED STAGE3
sleep 4

SERIAL_WRITE "--> LED SPECIAL2"
LED SPECIAL2
sleep 4

SERIAL_WRITE "--> LED CLEANUP"
LED CLEANUP
sleep 4

SERIAL_WRITE "--> LED FAIL"
LED FAIL
sleep 4

WAIT_FOR_KEY KEY1 15s "Press KEY1 within 15s to continue to color tests"
if [ $? -eq 0 ]; then
	SERIAL_WRITE "KEY1 pressed – continuing"
else
	SERIAL_WRITE "KEY1 not pressed (timeout)"
fi

# --- Section 2: Testing direct COLOR and PATTERN commands ---

SERIAL_WRITE "Testing COLOR commands..."
sleep 2

SERIAL_WRITE "--> RED (SOLID)"
LED R SOLID # 'SOLID' is default, can be omitted
sleep 3

SERIAL_WRITE "--> GREEN"
LED G
sleep 3

SERIAL_WRITE "--> BLUE"
LED B
sleep 3

SERIAL_WRITE "--> YELLOW"
LED Y
sleep 3

SERIAL_WRITE "--> CYAN"
LED C
sleep 3

SERIAL_WRITE "--> MAGENTA"
LED M
sleep 3

SERIAL_WRITE "--> WHITE"
LED W
sleep 3

WAIT_FOR_KEY KEY2 10s "Press KEY2 within 10s to continue to pattern tests"
if [ $? -eq 0 ]; then
	SERIAL_WRITE "KEY2 pressed – continuing"
else
	SERIAL_WRITE "KEY2 not pressed (timeout)"
fi

# --- Section 3: Testing PATTERN commands on a single color ---

SERIAL_WRITE "Testing PATTERN commands..."
sleep 2

SERIAL_WRITE "--> SLOW Blink"
LED C SLOW
sleep 5

SERIAL_WRITE "--> FAST Blink"
LED C FAST
sleep 4

SERIAL_WRITE "--> VERYFAST Blink"
LED C VERYFAST
sleep 4

SERIAL_WRITE "--> TRIPLE Blink"
LED C TRIPLE
sleep 4

SERIAL_WRITE "--> Inverted DOUBLE Blink"
LED C IDOUBLE
sleep 4

SERIAL_WRITE "--> Custom 250ms Blink"
LED C 250
sleep 4

# --- Section 4: Final Test ---

SERIAL_WRITE "Testing the SUCCESS pattern..."
LED FINISH # FINISH uses the SUCCESS pattern by default
SERIAL_WRITE "It blinks fast then goes solid."
sleep 5

SERIAL_WRITE "Showcase complete!"
sleep 2