#![allow(clippy::complexity, clippy::style, clippy::pedantic)]
extern crate openssl;
extern crate pem;
extern crate rcgen;
extern crate rustls_pemfile;
extern crate time;

use rcgen::{
    Certificate, CertificateParams, DistinguishedName, IsCa, KeyPair, KeyUsagePurpose, SanType,
};

use std::fs::File;
use std::io::{BufReader, Read};
use std::{env, fs};

fn main() {
    let args: Vec<String> = env::args().collect();
    let ca_cert: Certificate;

    if args.len() != 3 {
        println!("arg length is {}", args.len());
        for x in args {
            println!("{}", x)
        }
        panic!("Please enter either the path to an existing CA cert or 'new', This will generate a new CA. Then enter the subject name of the cert you want to create");
    }

    if args[1] == String::from("new") {
        ca_cert = create_ca_cert();
    } else {
        match read_root_cert(args[1].clone()) {
            Ok(cert) => {
                println!("Successfully read CA:");
                ca_cert = cert;
            }
            Err(err) => {
                panic!("Error: {:?}", err)
            }
        }
    }

    let dn_name = args[2].clone();
    signed_cert_with_ca(ca_cert, dn_name)
}

pub fn read_root_cert(ca_path: String) -> Result<Certificate, Box<dyn std::error::Error>> {
    // Open the PEM file containing both the certificate and private key

    let pem_cert_file = File::open(format!("{ca_path}.pem"))?;
    let mut pem_cert_reader = BufReader::new(pem_cert_file);

    let mut cert_string = String::new();
    pem_cert_reader.read_to_string(&mut cert_string)?;

    let pem_key_file = File::open(format!("{ca_path}.key"))?;
    let mut pem_key_reader = BufReader::new(pem_key_file);

    let mut key_pair_sting = String::new();
    pem_key_reader.read_to_string(&mut key_pair_sting)?;

    let key_pair = KeyPair::from_pem(key_pair_sting.as_str())?;

    // Parse the PEM file and create a new CertificateParams object
    let ca_cert_params = CertificateParams::from_ca_cert_pem(cert_string.as_str(), key_pair)?;

    // Create a new certificate using the CertificateParams object
    let ca_cert = Certificate::from_params(ca_cert_params)?;

    //let ca_sign = CertificateSigningRequest::from_per(ca_cert.serialize_pem_with_signer(ca))?;

    Ok(ca_cert)
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
        "certs/rootca.key",
        &cert.serialize_private_key_pem().as_bytes(),
    )
    .unwrap();
    cert
}

fn signed_cert_with_ca(ca_cert: Certificate, dn_name: String) {
    let mut dn = DistinguishedName::new();
    dn.push(rcgen::DnType::CommonName, dn_name.clone());

    let mut params = CertificateParams::default();

    params.distinguished_name = dn;
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
    let cert = Certificate::from_params(params).unwrap();

    let cert_signed = cert.serialize_pem_with_signer(&ca_cert).unwrap();

    let path = format!("certs/{dn_name}/");
    let cert_path = format!("certs/{dn_name}/{dn_name}.pem");
    let key_path = format!("certs/{dn_name}/{dn_name}.key");

    std::fs::create_dir_all(path).unwrap();
    fs::write(cert_path, cert_signed).unwrap();
    fs::write(key_path, &cert.serialize_private_key_pem().as_bytes()).unwrap();
}
