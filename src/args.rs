use clap::Clap;

#[derive(Clap)]
#[clap(version = "0.1", author = "Maxim Z.")]
pub struct Opts {
    /// Setting of the IP Time to Live.
    #[clap(short = "t")]
    pub ttl: Option<u32>,
    /// Time to wait for a response, in seconds..
    ///
    /// We are not handle the timeout properly yet.
    /// Thus currently you can only recognize the type of error by that.
    #[clap(short = "W")]
    pub read_timeout: Option<u32>,
    /// Stop after sending count ECHO_REQUEST packets.
    #[clap(short = "c")]
    pub count_packets: Option<usize>,
    /// The address ping which
    pub address: String,
}

pub fn config() -> Opts {
    Opts::parse()
}
