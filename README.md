# niping
`ping` implementation in rust

## Overview

`niping` is tend to be similar with original `ping` interface.
Currently it supports only IpV4 and a small bunch of options.

## Usage

You use it with cargo or build it by `cargo install`. And to open new socket you should have the correct right. Therefore you may do that under superuser.

#### Basic example.

```bash
$ sudo niping -c 4 rust-lang.org
PING 13.35.253.100 (rust-lang.org) 32 bytes of data
60 bytes from server-13-35-253-100.fra6.r.cloudfront.net. (13.35.253.100): icmp_seq=1 ttl=241 time=40 ms
60 bytes from server-13-35-253-100.fra6.r.cloudfront.net. (13.35.253.100): icmp_seq=2 ttl=241 time=40 ms
60 bytes from server-13-35-253-100.fra6.r.cloudfront.net. (13.35.253.100): icmp_seq=3 ttl=241 time=40 ms
60 bytes from server-13-35-253-100.fra6.r.cloudfront.net. (13.35.253.100): icmp_seq=4 ttl=241 time=41 ms

------- rust-lang.org statistics -------
4 packets transmitted, received 4, time 3220 ms
rtt min=40 ms max=41 ms avg=40 ms
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
