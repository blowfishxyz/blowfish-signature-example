use std::{
    env,
    fs::{self, File},
    io::Write,
    path::Path,
};

use anyhow::{anyhow, Context};
use ring::{rand, rsa, signature};

// Keys in DER format from the data directory
const PRIVATE_KEY_DER_PATH: &str = "../data/key.der";
const PUBLIC_KEY_DER_PATH: &str = "../data/key.pub.der";
const PUBLIC_PRODUCTION_KEY_DER_PATH: &str = "../data/prod/key.pub.der";

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
/// - `cargo run -- request`
///     Executes an API request to the production Blowfish Solana scan transactions API and
///     verifies the signature of the response with the public key.
fn main() {
    let private_key_path = Path::new(PRIVATE_KEY_DER_PATH);
    let public_key_path = Path::new(PUBLIC_KEY_DER_PATH);
    let public_prod_key_path = Path::new(PUBLIC_PRODUCTION_KEY_DER_PATH);

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
        "request" => request(public_prod_key_path).expect("request failed"),
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

/// Loads the public key in its DER format, makes a request to the API requesting a signature
/// from it and verifies that the received response body is properly signed
fn request(public_key_path: &std::path::Path) -> anyhow::Result<()> {
    // Verify the signature
    let public_key = signature::UnparsedPublicKey::new(
        &signature::RSA_PKCS1_2048_8192_SHA256,
        read_file(public_key_path)
            .map_err(|err| anyhow!("cannot read public key path: {err:?}"))?,
    );

    let api_key = env::var("API_KEY").context("API_KEY required for the current example")?;
    let response = reqwest::blocking::Client::new()
        .post("https://api.blowfish.xyz/solana/v0/mainnet/scan/transactions?language=en")
        .header("X-Api-Key", api_key)
        .header("content-type", "application/json")
        .header("accept", "application/json")
        .header("X-Api-Version", "2023-06-05")
        .header("x-blowfish-signed-response", "1.0")
        .body(r#"{"metadata": {"origin": "https://memecoinsair.eu/"}, "userAccount": "E5puyYXwbQgmS4rpnFScsZLDjigRMv1Z8PSCVxGkU6zX", "transactions": ["E6AXQVB9tpCSERL5Ws56a89ttMnsC6QD1GKnfpNNAEZ8cdTY1jqmW35Co9J888uK3Fd1xX3URcd9tPJ95se5jcs56RGWupdZPmXEXfuQnTz8tLotK7auH9otst9Unsj8vuhHf7sygNUK1ChSPYf3NvKvMS2oFdSLVBMdnpPS5hBKNvNdmnTMZfbfaCiiLhnhwhEGx4Vs3THjSxejJPqoPXccTkSUCkUgMSWDzEu2JogxjSifqyPWcQNwMKHDwgxZv5gLQw1W6h3mmC1stJ2rYA53cRt1rU1x1qeMcr72izhrUcnCfYQAeB4BAabuMSQ3HpXrDtZzUtQu1MqNBSYFANGvqiaN8su9RuuNeJz6DT4L42w2YaQRJKkmvTiGKaGq6YMiXxyXaurACopq8gWJGNeJQjrLmnB1sDosZKbbC5jf27x1cjY8mix1PTUsb7eK7CjY47KAtDHEMRbtWpp3V19dxTXaS3i5uyizuzo2Y1d7yPaJZ5qn2aL4hEFTJY4PeK7GoGBXSVcw7nPXfLCks8o7yo6tb2cotki2GSCdUgTs5G3akgG4KuSH5XzA32sCVuzq3z1XEHxrB3hcQ6FeL3WsDQ6TnejguppgSNrhJyMWRCzvVM6QDCnqmUARYfGcf9wBiQbQxjxdenQhKLNaM274F3DwMUYGL9sCueCnNQR3j6bYTnvSxfRXZ8t6RpHtHpJgL2yUN34sFxPXXCBwJnZHuScd13MiZ2A6TqRq7kij46LS5HQLe5sZNP7sTVtnRSKGLEttcV7TQCRvKTad7ueMdwDXWkcFFZvGey7T9DmUpoyQETjAz5uKdBMJsYmhrQt49nSuCdXQno2r1qRfA1RYDW"]}"#)
        .send() ?;

    let signature_hex = response
        .headers()
        .get("x-blowfish-signed-response")
        .context("signature not found")?
        .to_str()
        .context("signature cannot be converted to str")?
        .to_owned();
    let signature = hex::decode(signature_hex).unwrap();

    let response_body = response.text()?;

    public_key
        .verify(response_body.as_bytes(), &signature)
        .map_err(|err| anyhow!("bad signature: {err:?}"))?;

    println!("Signature verification completed successfully");

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
