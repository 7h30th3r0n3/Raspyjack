#!/bin/bash
# Script to kill processes using port 8000
PORT=8000
PIDS=$(lsof -w -t -i:$PORT 2>/dev/null)
if [ -n "$PIDS" ]; then
    echo "Killing the following PIDs using port $PORT: $PIDS"
    kill -9 $PIDS
else
    echo "No processes found using port $PORT"
fi

