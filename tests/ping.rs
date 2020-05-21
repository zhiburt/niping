use rexpect::{errors::*, process::wait::WaitStatus, spawn};

fn run(addr: &str, params: &[&str], packet_limit: usize) -> Result<usize> {
    let params = if params.is_empty() {
        "".to_owned()
    } else {
        " ".to_owned() + &params.join(" ")
    };
    let command = format!("./target/debug/niping {}{}", addr, params);
    let mut p = spawn(&command, Some(30_000))?;
    p.exp_regex("PING.*\n")?;

    let mut count = 0;
    while count != packet_limit {
        match p.process.status() {
            Some(WaitStatus::Exited(..)) => break,
            Some(..) => {
                p.read_line()?;
                count += 1
            }
            None => unreachable!(),
        }
    }

    Ok(count)
}

#[test]
fn ping() {
    let limit = 5;
    let packets = run("8.8.8.8", &[], limit);
    assert!(packets.is_ok());
    assert_eq!(packets.unwrap(), limit);
}

#[test]
fn ping_dns() {
    let limit = 5;
    let packets = run("rust-lang.org", &[], limit);
    assert!(packets.is_ok());
    assert_eq!(packets.unwrap(), limit);
}

#[test]
fn ping_localhost() {
    let limit = 5;
    let packets = run("127.0.0.1", &[], limit);
    assert!(packets.is_ok());
    assert_eq!(packets.unwrap(), limit);
}

#[test]
fn ping_option_count() {
    let limit = 5;
    let count = 2;
    let packets = run("8.8.8.8", &[&format!("-c {}", count)], limit);
    assert!(packets.is_ok());
    assert_eq!(packets.unwrap(), count);
}

#[test]
fn ping_option_count_dns() {
    let limit = 5;
    let count = 2;
    let packets = run("rust-lang.org", &[&format!("-c {}", count)], limit);
    assert!(packets.is_ok());
    assert_eq!(packets.unwrap(), count);
}
