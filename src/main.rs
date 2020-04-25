// : how we can calculate RTT

use crossbeam::channel::unbounded;
use niping::{args, ping, stats};
use std::net;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use trust_dns_resolver::config::*;
use trust_dns_resolver::Resolver;

fn main() {
    let opts = args::config();
    let address = match parse_address(&opts.address) {
        Some(addr) => addr,
        None => {
            println!("PING: {}: Name or service not known", opts.address);
            return;
        }
    };

    let ping = ping::Settings {
        addr: address.clone(),
        ttl: opts.ttl,
        read_timeout: opts.read_timeout,
        packets_limit: opts.count_packets,
        send_interval: opts
            .send_interval
            .map(|s| std::time::Duration::from_secs_f32(s)),
    }
    .build();

    let terminated = Arc::new(AtomicBool::new(true));
    let t = terminated.clone();
    ctrlc::set_handler(move || {
        t.store(false, Ordering::SeqCst);
    })
    .expect("Error setting Ctrl-C handler");

    let (packet_s, packet_r) = unbounded();

    let ping_handle = thread::spawn(move || ping.ping_loop(packet_s, terminated));
    let stats_handle = thread::spawn(move || {
        let stats = stats::Statistics::new(opts.address, address);
        stats.run(packet_r)
    });

    ping_handle.join().unwrap();
    stats_handle.join().unwrap();
}

fn parse_address(addr: &str) -> Option<net::IpAddr> {
    let resolver = Resolver::new(ResolverConfig::default(), ResolverOpts::default()).unwrap();
    let response = resolver.lookup_ip(addr);
    if let Ok(response) = response {
        let addr = response.iter().next().unwrap();
        return Some(addr);
    }

    None
}
