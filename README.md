ocaml-socks
===========
[![Build status](https://travis-ci.org/cfcs/ocaml-socks.svg?branch=master)](https://travis-ci.org/cfcs/ocaml-socks/)
SOCKS 4a / SOCKS 5 library for OCaml clients and servers
---------------------------------------------

This library implements functions for parsing and generating
SOCKS 4A and SOCKS 5 requests and responses.

A Lwt helper module is provided to ease integration in Lwt applications.
Unfortunately this module does not work with MirageOS.

### Limitations

- This is **not** a "SOCKS5 compliant" implementation since the RFC requires
  that compliant implementation `MUST` support GSSAPI, which this library does
  not.
- The Lwt helper module does not handle `BIND` or `UDP-associate`.
- The Lwt helper module does not implement client functionality.
  Eckhart Köppen has [a fork](https://github.com/ekoeppen/ocaml-socks5-client)
  that seems to implement this. A pull request to integrate this would be nice.

### Building

To avoid always linking against `Lwt`/`Async`/`MirageOS` and introducing huge
unneeded dependencies, this repository contains multiple OPAM packages:

- `socks`
- `socks-lwt`

A `Makefile` is provided for your convenience:

```shell
ocaml-socks$ make lib-lwt
ocaml-socks$ make docs
ocaml-socks$ make all
ocaml-socks$ make clean
```

### Generating the documentation

This module is documented using `mli` docstrings.
After installing the `topkg-care` OPAM package you can compile the documentation
to HTML for viewing in your browser like this:
```shell
ocaml-socks$ make docs
# No parallelism done
Generated API doc in /home/user/ocaml/socks/_build/doc/api.docdir/

ocaml-socks$ firefox /home/user/ocaml/socks/_build/doc/api.docdir/index.html
```

### Running a SOCKS server from utop

To run a SOCKS server listening on 127.0.0.1 (IPv4 localhost) port 1080
that accepts connections from IPv4/IPv6 localhost and connects to
IPv4/IPv6/Domain-name ATYPs, you can use the `easy_establish_server` function:
```ocaml
let s = Socks_lwt.easy_establish_server () ;;
Lwt_main.run s ;;
```

The documentation for `Socks_lwt` has more details on creating filters for
connecting clients.

### Resources

The protocol description is included in this repository in the files
- [SOCKS4.protocol.txt] and [SOCKS4A.protocol.txt] for `SOCKS 4` and
  the `SOCKS 4A` extension, respectively.
- [SOCKS5_rfc1928.txt] and [SOCKS5_rfc1929.txt] for `SOCKS 5`,
  and `SOCKS 5 Username/Password authentication`.

[SOCKS4.protocol.txt]: ./rfc/SOCKS4.protocol.txt
[SOCKS4A.protocol.txt]: ./rfc/SOCKS4A.protocol.txt
[SOCKS5_rfc1928.txt]: ./rfc/SOCKS5_rfc1928.txt
[SOCKS5_rfc1929.txt]: ./rfc/SOCKS5_rfc1929.txt
