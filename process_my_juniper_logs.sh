#!/bin/bash

if [[ "$1" == "-h" || "$1" == "--help" || "$1" == "help" ]]; then
cat << EOF
Usage: process_my_juniper_logs.sh %1 %2 %3

Helper script for processing srx log files.

Options:
-h, --help      Show this help
%1              srx hostname
%2              fullpath and name of file(s) to be parsed
%3              if present, any character will enable multi-threading across all cpu cores
				for performance gain

Examples:
./process_my_juniper_logs.sh john_doe /var/log/messages enable
./process_my_juniper_logs.sh john_doe /var/log/messages* enable
./process_my_juniper_logs.sh john_doe /var/log/messages disable
EOF
    exit 0
fi

rm -f *.csv
rm -f *.txt
rm -f messages*
rm -f *.log

MYMULTI=0

if [ -z "$1" ]; then
    exit 1
fi

if [ -z "$2" ]; then
    exit 1
fi

if [ -z "$3" ]; then
    MYMULTI=1
fi

cat $2 | grep $1 > messages

NUMLINES=$(cat $2 | wc -l)
SEGMENTS=$((NUMLINES/100000))

echo "NUMLINES = $NUMLINES SEGMENTS = $SEGMENTS"

awk '{print > "messages_"$1"_"$2"_"strftime("%Y")".log"}' messages

rm -f messages

MYSCRIPT_DIR="$(pwd)"

# Simple version (breaks on filenames with spaces or newlines)
for file in "$MYSCRIPT_DIR"/*; do
    if $MYMULTI == 1; then
        echo "python3 srx_report.py -p $file -v &"
        python3 srx_report.py -p $file &
    else
        echo "python3 srx_report.py -p $file -v"
        python3 srx_report.py -p $file
    fi
done

exit 0
