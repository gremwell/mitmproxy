#!/bin/sh -x

SCRIPT=$(realpath "$0")
SCRIPTPATH=$(dirname "$SCRIPT")

sudo docker exec -it mitmproxy-dvp /bin/bash
