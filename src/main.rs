use niping::{
    args,
    packet::icmp::PacketType,
    ping::{self, PacketInfo, PingError, Socket2, DATA_SIZE},
};
use std::{
    io,
    net::IpAddr,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::{self, Duration},
};
use trust_dns_resolver::config::*;
use trust_dns_resolver::Resolver;

const DEFAULT_SEND_INTERVAL: Duration = Duration::from_secs(1);
const DEFAULT_READ_TIMEOUT: Duration = Duration::from_secs(10);

fn main() {
    let opts = args::config();
    let address = match parse_address(&opts.address) {
        Some(addr) => addr,
        None => {
            println!("PING: {}: Name or service not known", opts.address);
            return;
        }
    };
    let wait_time = opts
        .send_interval
        .as_ref()
        .map_or(DEFAULT_SEND_INTERVAL, |secs| Duration::from_secs_f32(*secs));
    let read_timeout = opts
        .read_timeout
        .map_or(DEFAULT_READ_TIMEOUT, |s| Duration::from_secs(s as u64));
    let ttl = opts.ttl;
    let resource_name = opts.address;
    let count_packets = opts.count_packets;
    let p = ping::Settings {
        addr: address.clone(),
        ttl,
        read_timeout,
    }
    .build();

    let stop = Arc::new(AtomicBool::default());
    let stop_copy = stop.clone();
    ctrlc::set_handler(move || stop_copy.as_ref().store(true, Ordering::Relaxed)).unwrap();

    smol::run(run(
        p,
        wait_time,
        count_packets,
        stop,
        &address.to_string(),
        &resource_name,
    ));
}

async fn run(
    mut ping: ping::Ping<Socket2>,
    wait_time: Duration,
    count_packets: Option<usize>,
    stop: Arc<AtomicBool>,
    address: &str,
    resource: &str,
) {
    let mut transmitted = 0usize;
    let mut received = 0usize;
    let mut rtt: Vec<Duration> = Vec::new();
    let mut count_packets = count_packets;
    let time = time::Instant::now();

    println!(
        "PING {} ({}) {} bytes of data",
        address, resource, DATA_SIZE,
    );

    while !stop.as_ref().load(Ordering::Relaxed) {
        match count_packets.as_mut() {
            Some(0) => break,
            Some(count) => *count -= 1,
            None => (),
        }

        let packet = ping.run().await;
        match packet {
            Ok(packet) => {
                transmitted += 1;
                rtt.push(packet.time);
                if let Some(PacketType::EchoReply) = PacketType::new(packet.icmp_type) {
                    received += 1;
                }

                println!("{}", display_packet(packet));
            }
            Err(PingError::Send(err)) => println!("send: {}", io_error_to_string(err)),
            Err(PingError::Recv(err)) => println!("recv: {}", io_error_to_string(err)),
            Err(PingError::PacketError(..)) => println!("internal error"),
        }

        smol::Timer::after(wait_time).await;
    }

    let time = time.elapsed();

    let rtt_min = rtt.iter().min().unwrap();
    let rtt_max = rtt.iter().max().unwrap();
    let rtt_len = rtt.len();
    let rtt_avg = rtt.iter().sum::<Duration>() / rtt_len as u32;

    println!();
    println!("------- {} statistics -------", resource);
    println!(
        "{} packets transmitted, received {}, time {}",
        transmitted,
        received,
        display_duration(time)
    );
    println!(
        "rtt min/max/avg = {}/{}/{}",
        display_duration(*rtt_min),
        display_duration(*rtt_max),
        display_duration(rtt_avg),
    );
}

fn display_packet(info: PacketInfo) -> String {
    let specific_info = packet_info(&info);
    let dns_name =
        reverse_address(IpAddr::from(info.ip_source_ip)).map_or(String::from("gateway"), |n| n);

    format!(
        "{} bytes from {} ({}): {}",
        info.received_bytes, dns_name, info.ip_source_ip, specific_info
    )
}

fn packet_info(info: &PacketInfo) -> String {
    use PacketType::*;
    match PacketType::new(info.icmp_type) {
        Some(EchoReply) => format!(
            "icmp_seq={} ttl={} time={}",
            info.icmp_seq,
            info.ip_ttl,
            display_duration(info.time)
        ),
        Some(ref tp) => {
            let message = match tp {
                TimeExceeded => "time to live exceeded",
                DestinationUnreachable => "destination unreachable",
                ParameterProblem => "parameter problem",
                RedirectMessage => "redirect message",
                RouterAdvertisement => "router advertisement",
                RouterSolicitation => "router solicitation",
                Timestamp => "timestamp",
                TimestampReply => "timestamp reply",
                ExtendedEchoReply => "extended echo reply",
                EchoRequest => "echo request",
                ExtendedEchoRequest => "extended echo request",
                EchoReply => "echo reply",
            };

            format!("icmp_seq={} {}", info.icmp_seq, message)
        }
        None => format!(
            "icmp_seq={}, nonstandard packet {}",
            info.icmp_seq, info.icmp_type
        ),
    }
}

fn display_duration(d: Duration) -> String {
    format!("{:.2?}", d)
}

fn io_error_to_string(err: io::Error) -> String {
    format!("{}", err).to_lowercase()
}

fn reverse_address(addr: IpAddr) -> Option<String> {
    let resolver = Resolver::default().unwrap();
    let response = resolver.reverse_lookup(addr);
    if let Ok(response) = response {
        let addr = response.iter().next().unwrap();
        return Some(addr.to_string());
    }

    None
}

fn parse_address(addr: &str) -> Option<IpAddr> {
    let resolver = Resolver::new(ResolverConfig::default(), ResolverOpts::default()).unwrap();
    let response = resolver.lookup_ip(addr);
    if let Ok(response) = response {
        let addr = response.iter().next().unwrap();
        return Some(addr);
    }

    None
}
