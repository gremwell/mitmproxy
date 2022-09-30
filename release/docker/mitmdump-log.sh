#!/bin/sh -x

suffix="$1"
[ -z "$suffix" ] && exit 2

script -c \
	"ICD=9999 ./venv/bin/mitmdump --mode transparent --ssl-insecure -w dump.$suffix" \
	typescript.$suffix
