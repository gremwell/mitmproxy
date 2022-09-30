#!/bin/sh -x

suffix="$1"; shift
[ -z "$suffix" ] && exit 2

icd="$1"; shift
[ -z "$icd" ] && exit 2

script -c \
	"ICD=$icd ./venv/bin/mitmdump --mode transparent --ssl-insecure -w dump.$suffix" \
	typescript.$suffix
