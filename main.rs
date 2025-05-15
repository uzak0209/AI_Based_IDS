use chrono::{Date, DateTime, Local, Timelike, Utc};
use pnet::datalink::Channel::Ethernet;
use pnet::packet::arp::ArpPacket;
use pnet::packet::ethernet::{self, EtherTypes, EthernetPacket};
use pnet::packet::icmp::{Icmp, IcmpPacket};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::udp::UdpPacket;
use pnet::packet::Packet;
use pnet::packet::PacketSize;
use pnet::{datalink, packet};
use std::collections::HashMap;
use std::fs::File;
use std::io::{self, prelude::*};
use std::path::{Display, Path};
#[macro_use]
extern crate log;

use std::env;

mod packets;
use packets::GettableEndPoints;

const WIDTH: usize = 20;
use std::fmt;

enum Protocol {
    TCP,
    UDP,
    ICMP,
    ARP,
}

// store the value of counts
struct Count {
    syn: i32,
    ack: i32,
    port: HashMap<i32, i32>,
    traffic: i128,
    icmp: i32,
    arp: i32,
}
impl Count {
    fn ack_up(&mut self) {
        self.ack += 1;
    }
    fn syn_up(&mut self) {
        self.syn += 1;
    }
    fn add_port(&mut self, portnum: i32) {
        self.port
            .entry(portnum)
            .and_modify(|e| *e += 1)
            .or_insert(1);
    }
    fn traffic_up(&mut self, traffic_quantity: i128) {
        self.traffic += traffic_quantity;
    }
    fn icmp_up(&mut self) {
        self.icmp += 1;
    }
    fn arp_up(&mut self) {
        self.arp += 1;
    }
}
// DisplayトレイトをProtocol enumに実装
impl fmt::Display for Protocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // 各バリアントに対する文字列を返す
        match self {
            Protocol::TCP => write!(f, "TCP"),
            Protocol::UDP => write!(f, "UDP"),
            Protocol::ICMP => write!(f, "ICMP"),
            Protocol::ARP => write!(f, "ARP"),
        }
    }
}

fn main() {
    let path = Path::new("lorem_ipsum.txt");
    let path2=Path::new("data.txt");
    let display = path.display();
    let mut count: Count = Count::new();
    // Open a file in write-only mode, returns `io::Result<File>`
    let mut file2 = match File::create(&path2) {
        Err(why) => panic!("couldn't create {}: {}", display, why),
        Ok(_file) => _file,
    };
    let mut _file = match File::create(&path) {
        Err(why) => panic!("couldn't create {}: {}", display, why),
        Ok(_file) => _file,
    };
    io::stdout().flush().unwrap(); // プロンプトを即座に表示するためにflushを使用

    // ユーザー入力を格納する変数
    let mut input = String::new();

    // 標準入力からテキストを受け取る
    io::stdin().read_line(&mut input).unwrap();
    env::set_var("RUST_LOG", "debug");

    let interface_name = &input;

    // Select the network interface
    let interfaces = datalink::interfaces();
    let interface = interfaces
        .into_iter()
        .find(|iface| iface.name == *interface_name)
        .expect("Failed to get interface");
    let mut last_minute = get_current_minute();

    /* [1]: Get the datalink channel */
    let (_tx, mut rx) = match datalink::channel(&interface, Default::default()) {
        Ok(Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("Unhandled channel type"),
        Err(e) => panic!("Failed to create datalink channel {}", e),
    };

    loop {
        match rx.next() {
            Ok(frame) => {
                // Build the Ethernet frame from the received packet
                let frame = EthernetPacket::new(frame).unwrap();
                match frame.get_ethertype() {
                    EtherTypes::Ipv4 => {
                        ipv4_handler(&frame, &mut _file, &mut count);
                    }
                    EtherTypes::Ipv6 => {
                        ipv6_handler(&frame, &mut _file, &mut count);
                    }
                    EtherTypes::Arp => {
                        arp_handler(&frame, &mut _file, &mut count);
                    }
                    _ => {
                        info!("Not an IPv4 or IPv6");
                        count.traffic_up(frame.packet_size() as i128);
                    }
                }
                let minute = get_current_minute();
                if last_minute.abs_diff(minute) >= 1{
                    write_inf(&count,&mut file2);
                    last_minute = minute;
                }
            }

            Err(e) => {
                error!("Failed to read: {}", e);
            }
        }
    }
}
fn write_inf(count: &Count,file: &mut File) {
    let Str = format!(
        "{} {} {} {} {} {}\n",
        count.ack, count.syn, count.arp, count.icmp, count.traffic, count.port.len()
    );
    match file.write_all(Str.as_bytes()) {
        Err(why) => panic!("couldn't write to file: {}", why),
        Ok(_) => println!("Successfully wrote packet information"),
    }
}
fn arp_handler(ethernet: &EthernetPacket, _file: &mut File, mut count: &mut Count) {
    count.arp_up();
}
/**
 * 分数のみを返す
 */
fn get_current_minute() -> u32 {
    let now = Local::now();
    let minute = now.minute();
    minute
}

/**
 * カウントをリセット
*/
impl Count {
    fn reflesh(&mut self) {
        self.ack = 0;
        self.syn = 0;
        self.arp = 0;
        self.icmp = 0;
        self.traffic = 0;
        self.port = HashMap::new();
    }
    fn new() -> Self {
        Count {
            syn: 0,
            ack: 0,
            icmp: 0,
            traffic: 0,
            port: HashMap::new(),
            arp: 0,
        }
    }
}
/**
 * Process an IPv4 packet and call the next layer handler
 */
fn ipv4_handler(ethernet: &EthernetPacket, _file: &mut File, mut count: &mut Count) {
    if let Some(packet) = Ipv4Packet::new(ethernet.payload()) {
        match packet.get_next_level_protocol() {
            IpNextHeaderProtocols::Tcp => {
                tcp_handler(&packet, _file, &mut count);
            }
            IpNextHeaderProtocols::Udp => {
                udp_handler(&packet, _file, &mut count);
            }
            IpNextHeaderProtocols::Icmp => {
                icmp_handler(&packet, _file, &mut count);
            }
            _ => {
                info!("Not a TCP or UDP packet");
            }
        }
    }
}

fn icmp_handler(packet: &GettableEndPoints, _file: &mut File, count: &mut Count) {
    count.icmp_up();
    let source = packet.get_source2();
    let dist = packet.get_destination2();
    let information = format!("ICMP,{source},{dist}\n");
    match _file.write_all(information.as_bytes()) {
        Err(why) => panic!("couldn't write to file: {}", why),
        Ok(_) => println!("Successfully wrote packet information"),
    }
}

/**
 * Process an IPv6 packet and call the next layer handler
 */
fn ipv6_handler(ethernet: &EthernetPacket, _file: &mut File, mut count: &mut Count) {
    if let Some(packet) = Ipv6Packet::new(ethernet.payload()) {
        match packet.get_next_header() {
            IpNextHeaderProtocols::Tcp => {
                tcp_handler(&packet, _file, &mut count);
            }
            IpNextHeaderProtocols::Udp => {
                udp_handler(&packet, _file, &mut count);
            }
            _ => {
                info!("Not a TCP or UDP packet");
            }
        }
    }
}

/**
 * Process a TCP packet
 */
fn tcp_handler(packet: &GettableEndPoints, _file: &mut File, count: &mut Count) {
    fn is_set_synflag(flags: u8) -> bool {
        (flags & 0x02) != 0
    }
    fn is_set_ackflag(flags: u8) -> bool {
        (flags & 0x10) != 0
    }

    let tcp = TcpPacket::new(packet.get_payload2());
    if let Some(tcp) = tcp {
        let flags = tcp.get_flags();
        if is_set_synflag(flags) {
            count.syn_up();
        }
        if is_set_ackflag(flags) {
            count.ack_up();
        }
        count.add_port(tcp.get_source() as i32);
        count.add_port(tcp.get_destination() as i32);
        count.traffic_up(tcp.packet_size() as i128);
        write_packet_info(
            Protocol::TCP,
            packet.get_destination2(),
            packet.get_source2(),
            tcp.get_destination2(),
            tcp.get_source2(),
            _file,
        );
    }
}

/**
 * Process a UDP packet
 */
fn udp_handler(packet: &GettableEndPoints, _file: &mut File, count: &mut Count) {
    let udp = UdpPacket::new(packet.get_payload2());
    if let Some(udp) = udp {
        // Here you can handle UDP packets if needed.
        count.traffic_up(udp.packet_size() as i128);
        count.add_port(udp.get_source() as i32);
        count.add_port(udp.get_destination() as i32);

        write_packet_info(
            Protocol::UDP,
            packet.get_destination2(),
            packet.get_source2(),
            udp.get_destination2(),
            udp.get_source2(),
            _file,
        );
    }
}

/**
 * Write packet information to the file
 */
fn write_packet_info(
    proto: Protocol,
    dist_addr: String,
    source_addr: String,
    dist_port: String,
    source_port: String,
    file: &mut File,
) {
    let local_datetime: DateTime<Local> = Local::now();
    let information =
        format!("{local_datetime},{proto},{dist_addr},{source_addr},{dist_port},{source_port}\n");
    match file.write_all(information.as_bytes()) {
        Err(why) => panic!("couldn't write to file: {}", why),
        Ok(_) => println!("Successfully wrote packet information"),
    }
}
