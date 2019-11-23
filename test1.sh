#!/bin/bash

COMMANDER_PATH=$1
TEST_NAME=$2
BINARY_PATH=$3
FILE="$BINARY_PATH".dll

echo "Starting test: " "$BINARY_PATH" ":" "$TEST_NAME"

if test -f "$FILE"; then
	echo "$FILE exist"
else
	echo "$FILE NOT found!"
	exit 2
fi

$COMMANDER_PATH/bearcommander "$FILE" < "$BINARY_PATH"/"$TEST_NAME"_in.txt > "$BINARY_PATH"/"$TEST_NAME"_test.txt
DIFF_OUT=$(diff "$BINARY_PATH"/"$TEST_NAME"_out.txt "$BINARY_PATH"/"$TEST_NAME"_test.txt)

if [[ "$DIFF_OUT" == "" ]]; then
	echo "OK"
	exit 0
else
	echo "Failed"
	exit 1
fi

