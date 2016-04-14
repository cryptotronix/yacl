#!/bin/bash
if [ -d "/tmp/afl-ramdisk" ]
   echo "afl-ramdisk already exists"
else
    mkdir /tmp/afl-ramdisk
    chmod 777 /tmp/afl-ramdisk
    sudo mount -t tmpfs -o size=1024M tmpfs /tmp/afl-ramdisk
fi

AFL_SKIP_CPUFREQ=1 afl-fuzz -i b64urltest -o /tmp/afl-ramdisk ./afl
