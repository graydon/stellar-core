---
name: configuring-the-build
description: modifying build configuration to enable/disable variants, switch compilers or flags, or otherwise prepare for a build
---

# Overview

## Find the build directory first

Stellar Core is frequently built out-of-tree, especially in devcontainers.
Running `configure` or `make` in the source tree when an out-of-tree build is
already in use can contaminate the source tree and disrupt the existing build.

Before configuring or building:

1. Identify the source directory (normally `git rev-parse --show-toplevel`).
2. Check the current terminal directory and these common candidates for an
  already-configured build:
  - `../build`
  - `../core-build`
  - `./build` (relative to the source directory)
3. Treat a directory containing generated `Makefile`, `config.status`, and
  `config.log` files as a configured build tree. Prefer the existing build
  tree associated with the workspace or active terminal.
4. Run `make` and tests from the top level of that build tree, not from the
  source directory.

If no configured build exists, create a separate build directory by default
unless the user explicitly requests an in-tree build. Never start an in-tree
configuration merely because the source directory contains the `configure`
script.

The build works like this:
  - We start by running `./autogen.sh`
    - `autogen.sh` runs `autoconf` to turn `configure.ac` into `configure`
    - `autogen.sh` also runs `automake` to turn `Makefile.am` into `Makefile.in` and `src/Makefile.am` into `src/Makefile.in`
  - We then run the source tree's `configure` script from the chosen build
    directory (for example, `../stellar-core/configure` from `../core-build`)
    - `configure` turns `Makefile.in` into `Makefile` and `src/Makefile.in` into `src/Makefile`
    - `configure` also turns `config.h.in` into `config.h` that contains some variables 
    - `configure` also writes `config.log`, if there are errors they will be there

- ALWAYS run `./autogen.sh` from the source-tree top level
- ALWAYS run `configure` from the top level of the chosen build tree, using the
  source tree's `configure` script
- ALWAYS configure with `--enable-ccache` for caching
- ALWAYS configure with `--enable-sdfprefs` to inhibit noisy build output
- NEVER edit `configure` directly, only ever edit `configure.ac`
- NEVER edit `Makefile` or `Makefile.in` directly, only ever edit `Makefile.am`

To change configuration settings, re-run the source tree's `configure` script
with new flags from the existing build-tree top level.

You can see the existing configuration flags by looking at the head of `config.log`

## Configuration variables

To change compiler from clang to gcc, switch the value you pass for CC and CXX.
For example, from the build tree run
`CXX=g++ CC=gcc "$SOURCE_DIR/configure" ...` to configure with gcc. We want
builds to always work with gcc _and_ clang.

To alter compile flags (say turn on or off optimization, or debuginfo) change
CXXFLAGS. For example, from the build tree run
`CXXFLAGS='-O0 -g' "$SOURCE_DIR/configure" ...` to build
non-optimized and with debuginfo. Normally you should not have to change these.

Sometimes you will need to change to a different implementation of the C++
standard library. To do this, pass `-stdlib=libc++` or `-stdlib=libstdc++`
in `CXXFLAGS` explicitly. But again, normally you don't need to do this.

## Configuration flags

Here are some common configuration flags you might want to change:

  - `--disable-tests` turns off `BUILD_TESTS`, which excludes unit tests and all
    test-support infrastructure from core. We want this build variant to work
    since it is the one we ship, but it is uncommon when doing development.

  - `--disable-postgres` turns off postgresql backend support in core, leaving
    only sqlite. tests will run faster, and also this is a configuration we want
    to work (we will remove postgres entirely someday).
 
There are also some flags that turn on compile-time instrumentation for
different sorts of testing. Turn these on if doing specific diagnostic tests,
and/or to check for "anything breaking by accident". If you turn any on, you
will need to do a clean build -- the object files will have the wrong content.

  - `--enable-asan` turns on address sanitizer.
  - `--enable-threadsanitizer` same, but for thread sanitizer.
  - `--enable-memcheck` same, but for memcheck.
  - `--enable-undefinedcheck` same, but for undefined-behaviour sanitizer.
  - `--enable-extrachecks` turns on C++ stdlib debugging, slows things down.
  - `--enable-fuzz` builds core with fuzz instrumentation, plus fuzz targets.

There is more you can learn by reading `configure.ac` directly but the
instructions above ought to suffice for 99% of tasks. Try not to do anything
too strange with the configuration.

When in doubt, or if things get stuck, re-run `./autogen.sh` in the source tree
and then re-run the source tree's `configure` script from the existing build
tree. Do not fall back to configuring in the source tree.