#![allow(clippy::complexity, clippy::style, clippy::pedantic)]
extern crate openssl;
extern crate pem;
extern crate rcgen;
extern crate rustls_pemfile;
extern crate time;

use rcgen::RcgenError;
use rcgen::{
    Certificate, CertificateParams, DistinguishedName, IsCa, KeyPair, KeyUsagePurpose, SanType,
};
use rustls::PrivateKey;
use rustls_pemfile::{certs, rsa_private_keys};

use std::fs::{read_to_string, File};
use std::io::BufReader;
use std::{env, fs};

fn main() {
    let args: Vec<String> = env::args().collect();
    // let new_ca = use_or_create_ca(args, String::from("grimmy.co.uk"));

    // println!("new cert!: \n{}", new_ca.serialize_pem().unwrap());

    // let ca = create_ca_cert();
    // println!("CA: {}", ca.serialize_pem().unwrap());
    // let grimmy = signed_cert(&ca, String::from("foobar.co.uk"));
    // println!("grimmy.co.uk: {}", grimmy.serialize_pem().unwrap());
}

fn use_or_create_ca(args: Vec<String>, dn_name: String) -> Certificate {
    let ca: Certificate = {
        if args.len() > 1 {
            let ca_cert_path = args[1];
            // let ca_key_path = args[2];
            // let ca_cert = load_ca_certificate_and_key(&ca_cert_path, &ca_key_path).unwrap();
            // let ca_pem = ca_cert.0;
            let ca_pem = read_to_string(ca_cert_path).unwrap();
            println!("Using supplied CA");
            signed_cert_with_imported_ca(&ca_pem, dn_name)
        } else {
            println!("Generating new CA");
            create_ca_cert()
        }
    };
    ca
}

// fn load_ca_certificate_and_key(
//     ca_cert_path: &str,
//     ca_key_path: &str,
// ) -> Result<(Certificate, PrivateKey), RcgenError> {
//     // Read CA certificate file
//     let ca_cert_file = File::open(ca_cert_path).unwrap();
//     let mut ca_cert_reader = BufReader::new(ca_cert_file);
//     let ca_certs = certs(&mut ca_cert_reader).unwrap();

//     // Read CA private key file
//     let ca_key_file = File::open(ca_key_path).unwrap();
//     let mut ca_key_reader = BufReader::new(ca_key_file);
//     let ca_keys = rsa_private_keys(&mut ca_key_reader).unwrap();

//     if ca_certs.len() != 1 || ca_keys.len() != 1 {
//         return Err(RcgenError::CouldNotParseCertificate);
//     }

//     Ok((
//         rustls::Certificate(ca_certs[0].clone()),
//         rustls::PrivateKey(ca_keys[0].clone()),
//     ))
// }

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
        "certs/rootca.key",
        &cert.serialize_private_key_pem().as_bytes(),
    )
    .unwrap();
    cert
}

fn signed_cert(ca_cert: &Certificate, dn_name: String) -> Certificate {
    let key_pair = KeyPair::generate(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();

    let mut dn = DistinguishedName::new();
    dn.push(rcgen::DnType::CommonName, dn_name.clone());

    let mut params = CertificateParams::default();
    params.distinguished_name = dn;
    params.key_pair = Some(key_pair);
    params.not_before = time::OffsetDateTime::now_utc();
    params.not_after = time::OffsetDateTime::now_utc() + time::Duration::days(365 * 20);

    params.subject_alt_names = vec![
        SanType::DnsName(dn_name.clone()),
        SanType::DnsName(String::from("localhost")),
        SanType::IpAddress(std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1))),
        SanType::IpAddress(std::net::IpAddr::V6(std::net::Ipv6Addr::new(
            0, 0, 0, 0, 0, 0, 0, 1,
        ))),
    ];

    let cert = CertificateParams::from_params(params).unwrap();
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

fn signed_cert_with_imported_ca(ca_cert: &str, dn_name: String) -> Certificate {
    let key_pair = KeyPair::generate(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();

    let mut dn = DistinguishedName::new();
    dn.push(rcgen::DnType::CommonName, dn_name.clone());

    let mut params = CertificateParams::default();
    params.distinguished_name = dn;
    params.key_pair = Some(key_pair);
    params.not_before = time::OffsetDateTime::now_utc();
    params.not_after = time::OffsetDateTime::now_utc() + time::Duration::days(365 * 20);

    params.subject_alt_names = vec![
        SanType::DnsName(dn_name.clone()),
        SanType::DnsName(String::from("localhost")),
        SanType::IpAddress(std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1))),
        SanType::IpAddress(std::net::IpAddr::V6(std::net::Ipv6Addr::new(
            0, 0, 0, 0, 0, 0, 0, 1,
        ))),
    ];
    CertificateParams::from_ca_cert_pem(ca_cert, key_pair);

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
