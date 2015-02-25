#!/bin/sh

HERE=`dirname "$0"`
cd "$HERE"

scriptreplay demo-script.timings demo-script.txt $*
