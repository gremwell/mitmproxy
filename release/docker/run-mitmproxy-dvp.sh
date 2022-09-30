#!/bin/sh -x

SCRIPT=$(realpath "$0")
SCRIPTPATH=$(dirname "$SCRIPT")

sudo docker run -it --name mitmproxy-dvp --network host -v $SCRIPTPATH/../..:/mitmproxy mitmproxy-dvp /bin/bash
