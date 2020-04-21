# niping
`ping` implementation in rust

## Overview

`niping` is tend to be similar with original `ping` interface.
Currently it supports only IpV4 and a small bunch of options.

## Usage

You use it with cargo or build it by `cargo install`. And to open new socket you should have the correct right. Therefore you may do that under superuser.

#### Basic example.

```bash
$ sudo cargo run -- -c 4 rust-lang.org
PING 54.192.230.75 (rust-lang.org)
76 bytes from server-54-192-230-75.waw50.r.cloudfront.net. (54.192.230.75): icmp_seq=1 ttl=244 time=27 ms
76 bytes from server-54-192-230-75.waw50.r.cloudfront.net. (54.192.230.75): icmp_seq=2 ttl=244 time=28 ms
76 bytes from server-54-192-230-75.waw50.r.cloudfront.net. (54.192.230.75): icmp_seq=3 ttl=244 time=30 ms
76 bytes from server-54-192-230-75.waw50.r.cloudfront.net. (54.192.230.75): icmp_seq=4 ttl=244 time=28 ms

------- rust-lang.org statistics -------
5 packets transmitted, received 5, time 5147 ms
```

#### Example of a ttl option(`-t`)

```bash
> sudo niping -c 2 -t 2 google.com
PING 172.217.16.14 (google.com)
56 bytes from mm-1-0-45-37.brest.dynamic.pppoe.byfly.by. (37.45.0.1): icmp_seq=0 Time to live exceeded
56 bytes from mm-1-0-45-37.brest.dynamic.pppoe.byfly.by. (37.45.0.1): icmp_seq=0 Time to live exceeded

------- google.com statistics -------
2 packets transmitted, received 0, time 2018 ms
```
