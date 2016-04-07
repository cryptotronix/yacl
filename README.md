# yacl
Yet Another Crypto Library

[![Build Status](https://travis-ci.org/cryptotronix/yacl.svg?branch=master)](https://travis-ci.org/cryptotronix/yacl)

<a href="https://scan.coverity.com/projects/cryptotronix-yacl">
    <img alt="Coverity Scan Build Status"
    src="https://scan.coverity.com/projects/6244/badge.svg"/>
</a>

Basically this is my wrapper around a much better library (libsodium)
with some functions that libsodium doesn't include. In general, the
libsodium routines are used with the exception of the algorithms not
in NaCl, namely P-256 ECDSA/ECDH.

# Getting yacl

Probably best to pull the latest
[release](https://github.com/cryptotronix/yacl/releases). Otherwise,
you'll need autotools to build this from source. It follows the normal
autotools dance.


# Installing yacl

yacl can be installed in the normal fashion, with `sudo make
install`. I probably should make a .deb out of this to make it
easier...

# Using yacl

`yacl.h` is the public interface--that's the one file you need to
include. yacl uses `pkg-config` so you might find that the easiest way
to include it in your project.

Look in the `test` folder for example usage.

# Guile extensions

I have an odd fascinating with GNU Guile, so if you use the
`--with-guile` configuration option you can build the Guile
extensions. Under `test/guile`
