#![allow(clippy::complexity, clippy::style, clippy::pedantic)]
extern crate openssl;
extern crate pem;
extern crate rcgen;
extern crate time;

use rcgen::{
    Certificate, CertificateParams, DistinguishedName, IsCa, KeyPair, KeyUsagePurpose, SanType,
};
use std::fs;

fn main() {
    let ca = create_ca_cert();
    println!("{}", ca.serialize_pem().unwrap());
    let grimmy = signed_cert(&ca, String::from("foobar.co.uk"));
    println!("{}", grimmy.serialize_pem().unwrap());
}

fn create_ca_cert() -> Certificate {
    let key_pair = KeyPair::generate(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();

    let mut dn = DistinguishedName::new();
    dn.push(rcgen::DnType::CommonName, "rootca");

    let mut params = CertificateParams::default();
    params.is_ca = IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    params.distinguished_name = dn;
    params.key_pair = Some(key_pair);
    params.not_before = time::OffsetDateTime::now_utc();
    params.not_after = time::OffsetDateTime::now_utc() + time::Duration::days(365 * 20);

    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];

    let cert = Certificate::from_params(params).unwrap();

    let cert_pem = cert.serialize_pem().unwrap();

    std::fs::create_dir_all("certs/").unwrap();
    fs::write("certs/rootca.pem", &cert_pem.as_bytes()).unwrap();
    fs::write(
        "certs/rootca_key.pem",
        &cert.serialize_private_key_pem().as_bytes(),
    )
    .unwrap();
    cert
}

fn signed_cert(ca_cert: &Certificate, dn_name: String) -> Certificate {
    let key_pair = KeyPair::generate(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();

    let mut dn = DistinguishedName::new();
    dn.push(rcgen::DnType::CommonName, dn_name);

    let mut params = CertificateParams::default();
    params.distinguished_name = dn;
    params.key_pair = Some(key_pair);
    params.not_before = time::OffsetDateTime::now_utc();
    params.not_after = time::OffsetDateTime::now_utc() + time::Duration::days(365 * 20);

    params.subject_alt_names = vec![
        SanType::DnsName(String::from("localhost")),
        SanType::IpAddress(std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1))),
        SanType::IpAddress(std::net::IpAddr::V6(std::net::Ipv6Addr::new(
            0, 0, 0, 0, 0, 0, 0, 1,
        ))),
    ];

    let cert = Certificate::from_params(params).unwrap();
    let cert_signed = cert.serialize_pem_with_signer(ca_cert).unwrap();

    std::fs::create_dir_all("certs/").unwrap();
    fs::write("certs/cert.pem", &cert_signed.as_bytes()).unwrap();
    fs::write(
        "certs/key.pem",
        &cert.serialize_private_key_pem().as_bytes(),
    )
    .unwrap();

    cert
}
