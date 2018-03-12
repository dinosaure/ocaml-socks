ocaml-socks
===========
![Build status](https://travis-ci.org/cfcs/ocaml-socks.svg?branch=master)
SOCKS4a/SOCKS5 library for OCaml clients and servers
---------------------------------------------

This library implements functions for parsing and generating SOCKS4A and SOCKS5 requests and responses.
Tthe current version does not handle `BIND` since I haven't seen that in use anywhere.



### Resources

The protocol description is included in this repository in the files
- [SOCKS4.protocol.txt] and [SOCKS4A.protocol.txt] for SOCKS4 and the 4A extension, respectively.
- [SOCKS5_rfc1928.txt] and [SOCKS5_rfc1929.txt] for SOCKS5, and SOCKS5 Username/Password authentication.

[SOCKS4.protocol.txt]: ./rfc/SOCKS4.protocol.txt
[SOCKS4A.protocol.txt]: ./rfc/SOCKS4A.protocol.txt
[SOCKS5_rfc1928.txt]: ./rfc/SOCKS5_rfc1928.txt
[SOCKS5_rfc1929.txt]: ./rfc/SOCKS5_rfc1929.txt
