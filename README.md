# pkg2zip

Utility that decrypts PlayStation Vita pkg file and creates zip package.

Optionally saves [NoNpDrm](https://github.com/TheOfficialFloW/NoNpDrm) license into work.bin file. You must provide license key.

# Features

* **portable**, written in cross-platform C code, runs on Windows, GNU/Linux, macOS (system dependent functionality is isolated in sys.c file).
* **small**, uses zero dynamic memory allocations and has no external library dependencies.
* **fast**, uses AESNI hardware accelerated AES decryption if supported by CPU (requires [AESNI](https://en.wikipedia.org/wiki/AES_instruction_set) and [SSSE3](https://en.wikipedia.org/wiki/SSSE3) instructions).
* **simple**, creates zip package with same folder structure that Vita expects (just drag & drop all file from zip archive to ux0:). Zip file is created directly from pkg without any intermediate temporary files.

Limitations:
* currently works only for main application pkg files, no DLC.

# Usage

Execute `pkg2zip package.pkg` to create `title [id] [region].zip` file. Title, ID and region is automatically detected from pkg file.

If you have raw license key (32 hex characters) you can execute `pkg2zip package.pkg hexkey` to try to generate work.bin file (works for most pkg files).

If you have working zRIF string, then execute `pkg2zip package.pkg zRIF_string` to create work.bin file from zRIF encoding.

# Generating zRIF license

I you have working main.bin file you can create zRIF string with `rif2zrif.py` python script:

    $ python rif2zrif.py path/to/main.bin

It will print zRIF string to stdout.

# Download

Get latest Windows binaries [here](https://github.com/mmozeiko/pkg2zip/releases).

ArchLinux users can build binary with [pkg2zip](https://aur.archlinux.org/packages/pkg2zip/) package in AUR repository. For example, with pacaur:

    $ pacaur -S pkg2zip

# Building

Execute `make` if you are on GNU/Linux or macOS.

On Windows you can build either with MinGW (get [MinGW-w64](http://www.msys2.org/)) or [Visual Studio 2017 Community Edition](https://www.visualstudio.com/vs/community/).
* for MinGW make sure you have make installed, and then execute `mingw32-make`
* for Visual Studio run `build.cmd`

# Alternatives

* https://github.com/RikuKH3/unpkg_vita
* https://github.com/St4rk/PkgDecrypt
* https://github.com/TheRadziu/PkgDecrypt
* https://github.com/weaknespase/PkgDecrypt

# License

This is free and unencumbered software released into the public domain.

Anyone is free to copy, modify, publish, use, compile, sell, or distribute this software, either in source code form or as a compiled binary, for any purpose, commercial or non-commercial, and by any means.
