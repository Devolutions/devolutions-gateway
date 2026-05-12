use std::net::{IpAddr, Ipv4Addr};

use network_scanner::ip_utils::{IpAddrRange, Subnet};

#[test]
fn test_iter_ipv4() {
    let lower = "10.10.0.0".parse::<Ipv4Addr>().unwrap();
    let upper = "10.10.0.30".parse::<Ipv4Addr>().unwrap();
    let range = IpAddrRange::new_ipv4(lower, upper);

    let mut iter = range.into_iter();
    for i in 0..31 {
        let expected = format!("10.10.0.{i}").parse::<Ipv4Addr>().unwrap();
        assert_eq!(iter.next(), Some(IpAddr::V4(expected)));
    }
    assert_eq!(iter.next(), None);
}

#[test]
fn test_has_overlap() {
    let r1 = IpAddrRange::new_ipv4("192.168.1.0".parse().unwrap(), "192.168.1.255".parse().unwrap());
    let r2 = IpAddrRange::new_ipv4("192.168.1.100".parse().unwrap(), "192.168.2.10".parse().unwrap());
    assert!(r1.has_overlap(&r2));
}

#[test]
fn test_subnet_to_ip_range() {
    let subnet = Subnet {
        ip: Ipv4Addr::new(192, 168, 1, 0),
        netmask: Ipv4Addr::new(255, 255, 255, 0),
        broadcast: Ipv4Addr::new(192, 168, 1, 255),
    };

    let ip_range = IpAddrRange::from(subnet);

    let mut iter = ip_range.into_iter();

    for i in 0..256 {
        let expected = format!("192.168.1.{i}").parse::<Ipv4Addr>().unwrap();
        assert_eq!(iter.next(), Some(IpAddr::V4(expected)));
    }
}

#[test]
fn test_single_ipv4_range() {
    let address = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10));
    let mut iter = IpAddrRange::single(address).into_iter();

    assert_eq!(iter.next(), Some(address));
    assert_eq!(iter.next(), None);
}

#[test]
fn test_ipv4_intersection() {
    let left = IpAddrRange::new_ipv4(Ipv4Addr::new(192, 168, 1, 100), Ipv4Addr::new(192, 168, 2, 10));
    let right = IpAddrRange::new_ipv4(Ipv4Addr::new(192, 168, 1, 0), Ipv4Addr::new(192, 168, 1, 255));

    let intersection = left.intersection(&right).expect("ranges should overlap");

    assert_eq!(
        intersection.into_iter().collect::<Vec<_>>(),
        (100..=255)
            .map(|octet| IpAddr::V4(Ipv4Addr::new(192, 168, 1, octet)))
            .collect::<Vec<_>>()
    );
}
