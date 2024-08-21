use std::{
    env,
    fs::{self, File},
    io::Write,
    path::Path,
};

use ring::{rand, rsa, signature};

// Keys in DER format from the data directory
const PRIVATE_KEY_DER_PATH: &str = "../data/key.der";
const PUBLIC_KEY_DER_PATH: &str = "../data/key.pub.der";

// Data files to be used in the data directory
const MESSAGE_FILE_PATH: &str = "../data/data.txt";
const SIGNATURE_FILE_PATH: &str = "../data/data.txt.sign";

/// This example demonstrates how to sign and verify a message using RSA PKCS#1 v1.5 padding and the SHA256 digest algorithm.
///
/// Run this example with the following command:
/// - `cargo run -- sign`
///     Reads the keys in the data directory and signs the message in data.txt
///     creating a data.txt.sign file with the signature in hex format.
/// - `cargo run -- verify`
///     Reads the keys in the data directory and verifies the signature in the data.txt.sign file
///     against the message in data.txt.
fn main() {
    let private_key_path = Path::new(PRIVATE_KEY_DER_PATH);
    let public_key_path = Path::new(PUBLIC_KEY_DER_PATH);

    let args = env::args().collect::<Vec<_>>();

    // Validate number of arguments and print usage message
    if args.len() < 2 {
        println!(
            r#"ERROR: Missing operation argument
Usage: {} [sign|verify]"#,
            env::args().next().unwrap()
        );

        return;
    }

    match args[1].as_ref() {
        "sign" => sign(private_key_path).expect("sign failed"),
        "verify" => verify(public_key_path).expect("verify failed"),
        arg => {
            println!(
                r#"ERROR: Invalid operation argument {}
Usage: {} [sign|verify]"#,
                arg, args[0]
            );
        }
    }
}

/// Loads the private key in its DER format and signs the message in data.txt creating a
/// data.txt.sign file
fn sign(private_key_path: &std::path::Path) -> Result<(), SignError> {
    // Read the private key from the DER file and load the key pair
    let private_key_der = read_file(private_key_path)?;
    let key_pair =
        rsa::KeyPair::from_pkcs8(&private_key_der).map_err(|_| SignError::BadPrivateKey)?;

    // Read the message file contents
    let message = &read_file(Path::new(MESSAGE_FILE_PATH))?;

    // Sign the message using PKCS#1 v1.5 padding and the SHA256 digest algorithm.
    let rng = rand::SystemRandom::new();
    let mut signature = vec![0; key_pair.public().modulus_len()];
    key_pair
        .sign(&signature::RSA_PKCS1_SHA256, &rng, message, &mut signature)
        .map_err(|_| SignError::Oom)?;

    // Write the signature to a file as a hex string
    let hex_signature = hex::encode(&signature);
    File::create(Path::new(SIGNATURE_FILE_PATH))
        .map_err(SignError::IO)?
        .write_all(hex_signature.as_bytes())
        .map_err(SignError::IO)?;

    println!("Sign completed successfully");

    Ok(())
}

/// Loads the public key in its DER format and verifies the content in data.txt.sign against the
/// data.txt message file
fn verify(public_key_path: &std::path::Path) -> Result<(), SignError> {
    // Verify the signature
    let public_key = signature::UnparsedPublicKey::new(
        &signature::RSA_PKCS1_2048_8192_SHA256,
        read_file(public_key_path)?,
    );

    let message = &read_file(Path::new(MESSAGE_FILE_PATH))?;

    let signature_hex = fs::read_to_string(Path::new(SIGNATURE_FILE_PATH)).expect("read signature");
    let signature = hex::decode(signature_hex).unwrap();

    public_key
        .verify(message, &signature)
        .map_err(|_| SignError::BadSignature)?;

    println!("Signature verification completed successfully");
    Ok(())
}

/// Read file content in to a vector of bytes
fn read_file(path: &std::path::Path) -> Result<Vec<u8>, SignError> {
    use std::io::Read;

    let mut file = std::fs::File::open(path).map_err(SignError::IO)?;
    let mut contents: Vec<u8> = Vec::new();
    file.read_to_end(&mut contents).map_err(SignError::IO)?;

    Ok(contents)
}

#[derive(Debug)]
enum SignError {
    IO(std::io::Error),
    BadPrivateKey,
    Oom,
    BadSignature,
}

