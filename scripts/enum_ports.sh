#!/bin/bash

TARGET="127.0.0.1"
START_PORT=1
END_PORT=65535
TIMEOUT_SEC=1
CONCURRENCY=200

echo "Scanning $TARGET on ports $START_PORT–$END_PORT with up to $CONCURRENCY concurrent checks..."

# Generate list of ports, then use xargs to run socat in parallel
seq $START_PORT $END_PORT | \
  xargs -P $CONCURRENCY -n 1 -I{} bash -c \
    "timeout $TIMEOUT_SEC socat - TCP:$TARGET:{},connect-timeout=$TIMEOUT_SEC >/dev/null 2>&1 && echo \"Port {} is open\""