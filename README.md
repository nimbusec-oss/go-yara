# go-yara

[![GoDoc](https://godoc.org/github.com/hillu/go-yara?status.svg)](https://godoc.org/github.com/hillu/go-yara)

Go bindings for [YARA](http://plusvic.github.io/yara/), staying as
close as sensible to the library's C-API while taking inspiration from
the `yara-python` implementation.

YARA 3.3.0 or newer is required. For a version that supports some
features added to YARA after the 3.3.0 release, please use the
"master" branch.

## Installation

### Unix

On a Unix system with libyara properly installed, this should work,
provided that `GOPATH` is set:

    $ go get github.com/hillu/go-yara
    $ go install github.com/hillu/go-yara

Depending on what location libyara and its headers have been
installed, proper `CFLAGS` and `LDFLAGS` may have to be added to
`cgo.go` or be specified via environment variables (`CGO_CFLAGS` and
`CGO_LDFLAGS`)

### Windows

I have not yet built go-yara *on* Windows, only used the MinGW-w64
provided on Debian. The YARA library was built like this:

    $ ./configure --host=i686-w64-mingw32 --disable-magic --disable-cuckoo --without-crypto CFLAGS=-D__MINGW_USE_VC2005_COMPAT
    [...]
    $ make
    $ make install prefix=/path/to/i686-w64-mingw32

I found that the `CFLAGS` parameter was necessary to avoid problems
due to a missing `time32` symbol when linking 32bit Windows
executables.

Compiling and linking `go-yara` against this library was achieved like
this:

    $ CC=i686-w64-mingw32-gcc \
      CGO_ENABLED=1 \
      GOOS=windows GOARCH=386 \
      CGO_CFLAGS=-I/path/to/i686-w64-mingw32/include \
      CGO_LDFLAGS=-L/path/to/i686-w64-mingw32/lib \
      go install --ldflags '-extldflags "-static"' github.com/hillu/go-yara

## License

BSD 2-clause, see LICENSE file in the source distribution.

## Author

Hilko Bengen <bengen@hilluzination.de>
