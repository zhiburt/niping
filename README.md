# niping

`niping` is an implementation of `ping` protocol. It uses the ping(8) interface as an inspiration.

There's no support of ipv6 yet.

## Build

You can clone the repository and install `niping` by cargo or run it by `cargo run`.
Precisely you should have `rust` setup. 

```
git clone https://github.com/zhiburt/niping
cd niping
cargo install --path .
```

## Usage

You must to have correct permissions to open a socket.
So you may need `sudo`.

```bash
$ sudo niping -c 4 rust-lang.org
PING 52.222.149.19 (rust-lang.org) 32 bytes of data
60 bytes from server-52-222-149-19.fra53.r.cloudfront.net. (52.222.149.19): icmp_seq=1 ttl=242 time=76.28ms
60 bytes from server-52-222-149-19.fra53.r.cloudfront.net. (52.222.149.19): icmp_seq=2 ttl=242 time=87.67ms
60 bytes from server-52-222-149-19.fra53.r.cloudfront.net. (52.222.149.19): icmp_seq=3 ttl=242 time=92.12ms
60 bytes from server-52-222-149-19.fra53.r.cloudfront.net. (52.222.149.19): icmp_seq=4 ttl=242 time=88.29ms

------- rust-lang.org statistics -------
4 packets transmitted, received 4, time 3.40s
rtt min/max/avg = 76.28ms/92.12ms/86.09ms
```
