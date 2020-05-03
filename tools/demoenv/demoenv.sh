#!/bin/bash
cd $(dirname $0)
mkdir -p /tmp/kmgmdemo/.config/kmgm

termtosvg -t window_frame -g 120x30 -c ./sh_wrap.sh
