# `cert-gen`

This is a Rust function that generates a new SSL certificate and private key signed by a specified Certificate Authority (CA). The function takes two arguments:

-   `ca_cert`: A `Certificate` object representing the CA to sign the new certificate with.
-   `dn_name`: A `String` representing the domain name to generate the certificate for.

The function creates a new `DistinguishedName` object with the specified domain name, and a new `CertificateParams` object with the following properties:

-   `distinguished_name`: The `DistinguishedName` object with the specified domain name.
-   `not_before`: The current date and time.
-   `not_after`: The current date and time plus 20 years.
-   `subject_alt_names`: A `Vec<SanType>` containing the domain name, "localhost", and the IP addresses 127.0.0.1 and ::1.

The function then creates a new `Certificate` object using the `CertificateParams` object, and signs it with the specified CA using the `serialize_pem_with_signer` method. Finally, the function saves the signed certificate and private key files to disk in the `certs` directory within the directory you run the command from, with filenames based on the specified domain name.

## Usage

To use this function in your Rust code, you'll need to import the necessary crates and dependencies, and then call the function with the required arguments. Here's an example:

```rust
use rcgen::Certificate;
use signed_cert_with_ca;

// Assume `ca_cert` is a `Certificate` object representing the CA to sign the new certificate with.
let dn_name = "example.com".to_string();

signed_cert_with_ca(ca_cert, dn_name);
```

This will generate a new SSL certificate and private key for the domain example.com, signed by the specified CA.

## Dependencies

This function depends on the following Rust crates:

rcgen: Used to generate SSL certificates and private keys.
std::fs: Used to save the generated files to disk.

## License

This code is licensed under the MIT License. See the LICENSE file for details.

## Appreciation

This project would not been finished without the awesome help of brsnik and est31 so many thanks to them.
