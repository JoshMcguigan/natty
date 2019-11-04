// Copyright (c) 2014, 2015 Robert Clipsham <robert@octarineparrot.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

/// This example shows a basic packet logger using libpnet
use pnet::datalink::{self, NetworkInterface, DataLinkSender, DataLinkReceiver};

use pnet::packet::MutablePacket;
use pnet::packet::arp::MutableArpPacket;
use pnet::packet::ethernet::{EtherTypes, MutableEthernetPacket};
use pnet::packet::ipv4::MutableIpv4Packet;

use std::env;
use std::process;

use std::process::Command;

use tun_tap::{Iface, Mode};

/// Run a shell command. Panic if it fails in any way.
fn cmd(cmd: &str, args: &[&str]) {
    let ecode = Command::new("ip")
        .args(args)
        .spawn()
        .unwrap()
        .wait()
        .unwrap();
    assert!(ecode.success(), "Failed to execte {}", cmd);
}

fn do_tap_stuff(mac: String) -> Iface {
    let iface = Iface::without_packet_info("testtun%d", Mode::Tap).unwrap();
    cmd("ip", &["addr", "add", "dev", iface.name(), "10.107.1.51/24"]);
    cmd("ip", &["link", "set", "dev", iface.name(), "address", &mac]);
    cmd("ip", &["link", "set", "up", "dev", iface.name()]);
    println!("Created interface {}", iface.name());

    iface
}

fn transform_outbound_packet(mut buffer: &mut [u8], phy_interface_mac: pnet::datalink::MacAddr) -> Option<&mut [u8]> {
    let mut eth_packet = MutableEthernetPacket::new(&mut buffer)?;
    eth_packet.set_source(phy_interface_mac);
    match eth_packet.get_ethertype() {
        EtherTypes::Arp => {
            if let Some(mut arp_header) = MutableArpPacket::new(eth_packet.payload_mut()) {
                println!("[OUTBOUND-PRE-NAT] arp");
                println!("{:?}", arp_header);
                arp_header.set_sender_hw_addr(phy_interface_mac);
                // TODO only transform addresses within the configured subnet
                arp_header.set_sender_proto_addr(
                        transform_ip_addr(arp_header.get_sender_proto_addr(), 192, 168, 0)
                    );
                arp_header.set_target_proto_addr(
                        transform_ip_addr(arp_header.get_target_proto_addr(), 192, 168, 0)
                    );
                println!("[OUTBOUND-POST-NAT] arp");
                println!("{:?}", arp_header);
                return Some(buffer)
            }

            None
        }
        EtherTypes::Ipv4 => {
            if let Some(mut ipv4_packet) = MutableIpv4Packet::new(eth_packet.payload_mut()) {
                ipv4_packet.set_source(
                    transform_ip_addr(ipv4_packet.get_source(), 192, 168, 0)
                );
                ipv4_packet.set_destination(
                    transform_ip_addr(ipv4_packet.get_destination(), 192, 168, 0)
                );

                return Some(buffer)
            }

            None
        }
        _ => None
    }
}

fn transform_ip_addr(ip_addr: std::net::Ipv4Addr, a: u8, b: u8, c: u8) -> std::net::Ipv4Addr {
    // TODO this function currently only handles 24 bit subnets
    
    std::net::Ipv4Addr::new(a, b, c, ip_addr.octets()[3])
}

fn transform_inbound_packet(mut buffer: &mut [u8], tap_mac_addr: pnet::datalink::MacAddr) -> Option<&mut [u8]> {
    let mut eth_packet = MutableEthernetPacket::new(&mut buffer)?;
    // TODO only change destination to tap MAC if current destination is physical addr
    eth_packet.set_destination(tap_mac_addr);
    match eth_packet.get_ethertype() {
        EtherTypes::Arp => {
            if let Some(mut arp_header) = MutableArpPacket::new(eth_packet.payload_mut()) {
                println!("[INBOUND-PRE-NAT] arp");
                println!("{:?}", arp_header);
                arp_header.set_target_hw_addr(tap_mac_addr);
                arp_header.set_sender_proto_addr(
                        transform_ip_addr(arp_header.get_sender_proto_addr(), 10, 107, 1)
                    );
                arp_header.set_target_proto_addr(
                        transform_ip_addr(arp_header.get_target_proto_addr(), 10, 107, 1)
                    );
                println!("[INBOUND-POST-NAT] arp");
                println!("{:?}", arp_header);
                return Some(buffer)
            }

            None
        }
        EtherTypes::Ipv4 => {
            if let Some(mut ipv4_packet) = MutableIpv4Packet::new(eth_packet.payload_mut()) {
                ipv4_packet.set_source(
                    transform_ip_addr(ipv4_packet.get_source(), 10, 107, 1)
                );
                ipv4_packet.set_destination(
                    transform_ip_addr(ipv4_packet.get_destination(), 10, 107, 1)
                );

                return Some(buffer)
            }

            None
        }
        _ => None
    }
}


/// Forwards traffic from the TAP to the physical interface
fn outbound(tap_interface: &Iface, mut phy_interface_sender: Box<dyn DataLinkSender + 'static>,
    phy_interface_mac: pnet::datalink::MacAddr) {
    let mut buffer = vec![0; 1500];
    loop {
        let size = tap_interface.recv(&mut buffer).unwrap();
        if let Some(buffer) = transform_outbound_packet(&mut buffer[..size], phy_interface_mac) {
            phy_interface_sender.send_to(&buffer, None).unwrap().unwrap();
        }
    }
}

/// Forwards traffic from the physical interface to the TAP
fn inbound(tap_interface: &Iface, mut phy_interface_receiver: Box<dyn DataLinkReceiver + 'static>,
    tap_mac_addr: pnet::datalink::MacAddr) {
    loop {
        match phy_interface_receiver.next() {
            Ok(buffer) => {
                let mut buffer: Vec<u8> = buffer.to_owned();
                if let Some(buffer) = transform_inbound_packet(&mut buffer, tap_mac_addr) {
                    tap_interface.send(&buffer).unwrap();
                }
            }
            Err(e) => panic!("packetdump: unable to receive packet: {}", e),
        }
    }
}

fn main() {
    use pnet::datalink::Channel::Ethernet;

    let iface_name = match env::args().nth(1) {
        Some(n) => n,
        None => {
            eprintln!("USAGE: packetdump <NETWORK INTERFACE>");
            process::exit(1);
        }
    };
    let interface_names_match = |iface: &NetworkInterface| iface.name == iface_name;

    // Find the network interface with the provided name
    let interfaces = datalink::interfaces();
    let interface = interfaces
        .into_iter()
        .find(interface_names_match)
        .unwrap();

    let tap_interface = do_tap_stuff(format!("{}", interface.mac.unwrap()));
    let tap_mac_addr = datalink::interfaces()
        .into_iter()
        .find(|iface: &NetworkInterface| tap_interface.name() == &iface.name)
        .unwrap()
        .mac
        .unwrap();

    // Create a channel to receive on
    let (phy_interface_sender, phy_interface_receiver) = 
        match datalink::channel(&interface, Default::default()) {
            Ok(Ethernet(tx, rx)) => (tx, rx),
            Ok(_) => panic!("packetdump: unhandled channel type"),
            Err(e) => panic!("packetdump: unable to create channel: {}", e),
        };

    let inbound_tap = &tap_interface;
    let outbound_tap = &tap_interface;
    let phy_interface_mac = interface.mac.unwrap();
    crossbeam::thread::scope(move |s| {
        s.spawn(move |_| {
            inbound(inbound_tap, phy_interface_receiver, tap_mac_addr);
        });
        s.spawn(move |_| {
            outbound(outbound_tap, phy_interface_sender, phy_interface_mac);
        });
    }).unwrap();
}
