/// This is a Rust script that generates SSL certificates for use in local development environments.
///
/// It takes two command-line arguments: the first is either the path to an existing CA file or the
/// string "new" to create a new CA; the second is the domain name you wish to create a certificate for.
///
/// The script uses the `rcgen` crate to generate a new certificate and key pair, then signs the certificate
/// with the specified CA. It saves the certificate and key files to disk in the `certs` directory.
///
/// Usage:
/// ```
/// $ cargo run -- args...
/// ```

#[allow(clippy::complexity, clippy::style, clippy::pedantic)]
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
use std::process::exit;
use std::{env, fs};

/// This is the main entry point for the program.
///
/// First it checks that the correct number of arguments have been passed in,
/// then it checks if the first argument is "new" to create a new CA, or the path to an existing CA file.
///
/// The second argument is the domain name to generate the certificate for.
///
/// both are passed into the `signed_cert_with_ca` function to generate a new certificate and key pair
/// signed by the specified CA.

fn main() {
    let args: Vec<String> = env::args().collect();
    let ca_cert: Certificate;

    if args.len() != 3 {
        println!(
            "There should be two arguments passed into this command \
            the first is either the path to an existing ca file without any extensions \
            or `new` which will create a new ca for you. The second argument should be \
            the name of the domain you wish to create, for example `foobar.co.uk` instead \
            you have passed in {} arguments",
            args.len()
        );
        exit(1);
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

/// Reads an existing CA certificate and private key from the specified PEM files.
///
/// # Arguments
///
/// * `ca_path` - The path to the CA file without any extension (e.g. "certs/rootca").
///
/// # Returns
///
/// The `Certificate` object for the CA, or an error if the PEM files could not be read or parsed.

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

    Ok(ca_cert)
}

/// Generates a new CA certificate and private key.
///
/// # Returns
///
/// The `Certificate` object for the new CA.

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

/// Generates a new SSL certificate and private key signed by the specified CA.
///
/// # Arguments
///
/// * `ca_cert` - The `Certificate` object for the CA to sign the new certificate with.
/// * `dn_name` - The domain name to generate the certificate for.

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
