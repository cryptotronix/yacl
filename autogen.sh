#!/bin/sh -e
# Copyright (C) 2014 Cryptotronix, LLC.

if [ ! -d "m4" ]; then
    mkdir m4
fi

if [ ! -e "config.rpath" ]; then
    touch config.rpath
fi
autoreconf --force --install
