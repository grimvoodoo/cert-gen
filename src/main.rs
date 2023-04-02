#![allow(clippy::complexity, clippy::style, clippy::pedantic)]
extern crate openssl;
extern crate pem;
extern crate rcgen;
extern crate rustls_pemfile;
extern crate time;

use rcgen::{
    Certificate, CertificateParams, DistinguishedName, IsCa, KeyPair, KeyUsagePurpose, SanType,
};

use std::fs::read_to_string;
use std::{env, fs};

fn main() {
    let args: Vec<String> = env::args().collect();
    use_or_create_ca(args, String::from("grimmy.co.uk"));

    // println!("new cert!: \n{}", new_ca.serialize_pem().unwrap());

    // let ca = create_ca_cert();
    // println!("CA: {}", ca.serialize_pem().unwrap());
    // let grimmy = signed_cert(&ca, String::from("foobar.co.uk"));
    // println!("grimmy.co.uk: {}", grimmy.serialize_pem().unwrap());
}

fn use_or_create_ca(args: Vec<String>, dn_name: String) {
    let ca = {
        if args.len() > 1 {
            let ca_cert_path = &args[1];
            // let ca_key_path = args[2];
            // let ca_cert = load_ca_certificate_and_key(&ca_cert_path, &ca_key_path).unwrap();
            // let ca_pem = ca_cert.0;
            let ca_pem = read_to_string(ca_cert_path).unwrap();
            println!("Using supplied CA");
            signed_cert_with_imported_ca(&ca_pem, dn_name)
        } else {
            println!("Generating new CA");
            let ca_cert = create_ca_cert();
            signed_cert(&ca_cert, dn_name)
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

fn signed_cert(ca_cert: &Certificate, dn_name: String) {
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

    let cert = Certificate::from_params(params).unwrap();
    let cert_signed = cert.serialize_pem_with_signer(ca_cert).unwrap();

    let path = format!("certs/{dn_name}/");
    let cert_path = format!("certs/{dn_name}/{dn_name}.pem");
    let key_path = format!("certs/{dn_name}/{dn_name}.key");

    std::fs::create_dir_all(path).unwrap();
    fs::write(cert_path, &cert_signed.as_bytes()).unwrap();
    fs::write(key_path, &cert.serialize_private_key_pem().as_bytes()).unwrap();
}

fn signed_cert_with_imported_ca(ca_cert: &str, dn_name: String) {
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
    let ca_keypair = KeyPair::generate(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let ca = CertificateParams::from_ca_cert_pem(ca_cert, ca_keypair).unwrap();

    let ca_cert_combined = Certificate::from_params(ca).unwrap();

    let cert = Certificate::from_params(params).unwrap();

    let cert_signed = cert.serialize_pem_with_signer(&ca_cert_combined).unwrap();

    let path = format!("certs/{dn_name}/");
    let cert_path = format!("certs/{dn_name}/{dn_name}.pem");
    let key_path = format!("certs/{dn_name}/{dn_name}.key");

    std::fs::create_dir_all(path).unwrap();
    fs::write(cert_path, &cert_signed.as_bytes()).unwrap();
    fs::write(key_path, &cert.serialize_private_key_pem().as_bytes()).unwrap();
}

// fn signed_cert_with_imported_ca() {
//     let ca_cert_pem = include_str!("certs/rootca.pem");
//     let ca_key_pem = include_str!("path/to/your/ca_key.pem");

//     let ca_cert = X509::from_pem(ca_cert_pem.as_bytes()).unwrap();
//     let ca_key = PKey::private_key_from_pem(ca_key_pem.as_bytes()).unwrap();

//     let rsa = Rsa::generate(2048).unwrap();
//     let key = PKey::from_rsa(rsa).unwrap();

//     let mut name = X509Name::builder().unwrap();
//     name.append_entry_by_nid(Nid::COMMONNAME, "example.com")
//         .unwrap();
//     let name = name.build();

//     let mut req_builder = X509ReqBuilder::new().unwrap();
//     req_builder.set_subject_name(&name).unwrap();
//     req_builder.set_pubkey(&key).unwrap();
//     let req = req_builder.sign(&key, MessageDigest::sha256()).unwrap();

//     let mut cert_builder = X509::builder().unwrap();
//     cert_builder.set_version(2).unwrap();
//     cert_builder.set_subject_name(&name).unwrap();
//     cert_builder.set_pubkey(&key).unwrap();
//     cert_builder
//         .set_not_before(
//             &*SystemTime::now()
//                 .duration_since(SystemTime::UNIX_EPOCH)
//                 .unwrap()
//                 .as_secs(),
//         )
//         .unwrap();
//     let not_after = SystemTime::now() + Duration::from_secs(31536000); // One year
//     cert_builder
//         .set_not_after(
//             &*not_after
//                 .duration_since(SystemTime::UNIX_EPOCH)
//                 .unwrap()
//                 .as_secs(),
//         )
//         .unwrap();

//     let serial_number = openssl::bn::BigNum::from_u32(1)
//         .unwrap()
//         .to_asn1_integer()
//         .unwrap();
//     cert_builder.set_serial_number(&serial_number).unwrap();

//     cert_builder
//         .set_issuer_name(ca_cert.subject_name())
//         .unwrap();

//     let san = SubjectAlternativeName::new()
//         .dns("example.com")
//         .dns("www.example.com")
//         .build(&cert_builder.x509v3_context(Some(&ca_cert), None))
//         .unwrap();
//     cert_builder.append_extension(san).unwrap();

//     let basic_constraints = BasicConstraints::new().build().unwrap();
//     cert_builder.append_extension(basic_constraints).unwrap();

//     cert_builder
//         .set_issuer_name(ca_cert.subject_name())
//         .unwrap();
//     cert_builder.sign(&ca_key, MessageDigest::sha256()).unwrap();

//     let cert = cert_builder.build();

//     let cert_pem = cert.to_pem().unwrap();
//     let key_pem = key.private_key_to_pem_pkcs8().unwrap();

//     println!("Certificate:\n{}", String::from_utf8(cert_pem).unwrap());
//     println!("Private Key:\n{}", String::from_utf8(key_pem).unwrap());
// }
