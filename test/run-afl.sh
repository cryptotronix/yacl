#!/bin/bash
if [ "$#" -eq 0 ]; then
    echo "usage: $0 RAMDISK_MNT"
    exit 1
fi

AFL_RAMDISK=$1
AFL_INPUT_DIR=$2
AFL_TEST_PROG=$3

if [ -d "$AFL_RAMDISK" ]
then   
   echo "afl-ramdisk already exists"
else
    mkdir $AFL_RAMDISK
    chmod 777 $AFL_RAMDISK
    sudo mount -t tmpfs -o size=1024M tmpfs $AFL_RAMDISK
fi

AFL_SKIP_CPUFREQ=1 afl-fuzz -i $AFL_INPUT_DIR -o $AFL_RAMDISK $AFL_TEST_PROG
