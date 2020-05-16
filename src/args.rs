use clap::Clap;

#[derive(Clap)]
#[clap(
    author = "Maxim Z. <zhiburt@gmail.com>",
    about = "
Niping is an implementation of ping in rust. 
It mimics the interface of original ping."
)]
pub struct Opts {
    /// Setting of the IP Time to Live.
    #[clap(short = "t")]
    pub ttl: Option<u32>,
    /// Time to wait for a response, in seconds.
    #[clap(short = "W", name="timeout")]
    pub read_timeout: Option<u32>,
    /// Stop after sending count ECHO_REQUEST packets.
    #[clap(short = "c", name="count")]
    pub count_packets: Option<usize>,
    /// Wait interval seconds between sending each packet. The default value is 1 second.
    #[clap(short = "i", name="interval")]
    pub send_interval: Option<f32>,
    /// The address ping which
    pub address: String,
}

pub fn config() -> Opts {
    Opts::parse()
}
