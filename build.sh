#!/bin/bash

set -x

cd /root
rm -rf logscan_build && mkdir logscan_build && cd logscan_build
cmake -G "Unix Makefiles" -DCMAKE_BUILD_TYPE=Debug ../logscan_project
make
