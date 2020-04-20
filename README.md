# niping
`ping` implementation in rust

## Overview

`niping` is tend to be similar with original `ping` interface.
Currently it supports only IpV4 and a small bunch of options.

> There are not well structured moments yet.
>
> Error handling, I decided to left it in `.unwrap()` style in order to get advantage in faster develop process.
>
> Initial read timeout should be calculated as RTT * 2, but I have no idea yet how to calculate RTT initially.
>
> Connection to host. Original implementation of ping does a bit different thing which we do, as I can say it make connection after reaching the remote host. And may be it calculates RTT here. It's vital factor since if you run two process in place they will interfere without the connection. Nevertheless I might be wrong about the connection. But this is the best idea I hold ([Example](example-of-the-spoiled-socket)).


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

#### Example of the spoiled socket

If we start for example ping in the time `niping` working they will interfere. We just get unknown packets. The problem can be resolved by the uniq playground in ICMP header but the algorithm is crushed when we set `-t` option so the packets has incorrect playgrounds.

```bash
> sudo niping google.com
PING 216.58.209.14 (google.com)
76 bytes from waw02s18-in-f14.1e100.net. (216.58.209.14): icmp_seq=1 ttl=54 time=42 ms
84 bytes from fra16s42-in-f14.1e100.net. (172.217.18.110): icmp_seq=24 ttl=54 time=0 ms
^C
------- google.com statistics -------
2 packets transmitted, received 2, time 2044 ms
```