use std::fs;
use std::io::Write;
use std::path::Path;
use std::{env, fs::File};

use ring::{rand, rsa, signature};

const PRIVATE_KEY_DER_PATH: &str = "../data/key.der";
const PUBLIC_KEY_DER_PATH: &str = "../data/key.pub.der";

const MESSAGE_FILE_PATH: &str = "../data/data.txt";
const SIGNATURE_FILE_PATH: &str = "../data/data.txt.sign";

fn main() -> anyhow::Result<()> {
    let private_key_path = Path::new(PRIVATE_KEY_DER_PATH);
    let public_key_path = Path::new(PUBLIC_KEY_DER_PATH);

    if env::args().len() < 2 {
        println!(
            r#"ERROR: Missing operation argument
Usage: {} [sign|verify]"#,
            env::args().next().unwrap()
        );
        return Ok(());
    }

    let args = env::args().collect::<Vec<_>>();

    match args[1].as_ref() {
        "sign" => sign(private_key_path).expect("sign failed"),
        "verify" => verify(public_key_path).expect("verify failed"),
        arg => {
            println!(
                r#"ERROR: Invalid operation argument {}
Usage: {} [sign|verify]"#,
                arg, args[0]
            );
            return Ok(());
        }
    }

    Ok(())
}

fn sign(private_key_path: &std::path::Path) -> Result<(), SignError> {
    // Create an RSA keypair from the DER-encoded bytes. This example uses
    // a 2048-bit key, but larger keys are also supported.
    let private_key_der = read_file(private_key_path)?;
    let key_pair =
        rsa::KeyPair::from_pkcs8(&private_key_der).map_err(|_| SignError::BadPrivateKey)?;

    // Sign the message using PKCS#1 v1.5 padding and the SHA256 digest algorithm.
    let message = &read_file(Path::new(MESSAGE_FILE_PATH))?;

    let rng = rand::SystemRandom::new();
    let mut signature = vec![0; key_pair.public().modulus_len()];
    key_pair
        .sign(&signature::RSA_PKCS1_SHA256, &rng, message, &mut signature)
        .map_err(|_| SignError::Oom)?;

    let hex_signature = hex::encode(&signature);

    File::create(Path::new(SIGNATURE_FILE_PATH))
        .map_err(SignError::IO)?
        .write_all(hex_signature.as_bytes())
        .map_err(SignError::IO)?;

    println!("Sign completed successfully");
    Ok(())
}

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

#[derive(Debug)]
enum SignError {
    IO(std::io::Error),
    BadPrivateKey,
    Oom,
    BadSignature,
}

fn read_file(path: &std::path::Path) -> Result<Vec<u8>, SignError> {
    use std::io::Read;

    let mut file = std::fs::File::open(path).map_err(SignError::IO)?;
    let mut contents: Vec<u8> = Vec::new();
    file.read_to_end(&mut contents).map_err(SignError::IO)?;

    Ok(contents)
}
