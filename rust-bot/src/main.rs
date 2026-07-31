//! WoT Bot — Real BigWorld protocol using wg-toolkit-rs
//! Step 1: Send PING to WoT EU server, receive reply

use std::net::{SocketAddrV4, Ipv4Addr, SocketAddr};
use std::time::Duration;

use wgtk::net::socket::PacketSocket;
use wgtk::net::bundle::Bundle;
use wgtk::net::app::login::element::Ping;

fn main() {
    let server = "login.p1.worldoftanks.eu:20016";
    let server_addr: SocketAddr = match server.to_socket_addrs()
        .unwrap_or_else(|_| std::net::ToSocketAddrs::to_socket_addrs(&("login.p1.worldoftanks.eu", 20016)).unwrap())
        .next()
    {
        Some(addr) => addr,
        None => { eprintln!("DNS failed"); std::process::exit(1); }
    };

    println!("WoT Bot — Target: {}", server_addr);

    let local = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0));
    let mut socket = match PacketSocket::bind(local) {
        Ok(s) => s,
        Err(e) => { eprintln!("Bind failed: {}", e); std::process::exit(1); }
    };
    socket.set_recv_timeout(Some(Duration::from_secs(5))).ok();

    // Build PING bundle
    let mut bundle = Bundle::new();
    bundle.element_writer().write_simple(&Ping { num: 0 });

    println!("Sending PING...");
    match socket.send_bundle_without_encryption(&bundle, server_addr) {
        Ok(n) => println!("Sent {} bytes", n),
        Err(e) => { eprintln!("Send error: {}", e); std::process::exit(1); }
    }

    println!("Waiting for reply (5s timeout)...");
    match socket.recv_without_encryption() {
        Ok((packet, addr)) => {
            let data = packet.slice();
            let hex: String = data.iter().take(64).map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join(" ");
            println!("✅ REPLY from {} — {} bytes", addr, packet.len());
            println!("Prefix: {:08x}  Flags: {:04x}", packet.read_prefix(), packet.read_flags());
            println!("Hex: {}", hex);
        }
        Err(e) => {
            eprintln!("❌ No reply: {}", e);
            eprintln!("\nIf timeout: UDP is blocked on this network.");
            eprintln!("Try: VPS with full UDP, or different VPN.");
        }
    }
}
