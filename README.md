
# Sign example

The following example walks you through how to get started by creating and importing a keystore file, extracting and importing the public keys in the required formats and verifying the contents of a sample data file using both implementations in Rust and Node.js.

The workflow to be used:
1. Creates a pair of 4096-bit RSA private and public keys, in both PEM and DER formats
2. Imports a signature persisted in HEX format and a file with plain text contents
3. Recreates the original byte array representation and hashes it using SHA-256
4. And finally uses the public key provided to verify the data contents matches the signature provided

## Generate keys

In order to get us started, we will need a set of keys to be used for signing and verifing the contents of the dataprovided.

Create a private/public key pair based on RSA in PEM format.
```bash
openssl genrsa -out key.pem 4096
```

Output the DER representation of the private key, needed for the Rust signing implementation.
```bash
openssl rsa -in key.pem \
            -inform PEM \
            -outform DER \
            -out key.der
```

Extract a public key from the private one in DER representation to be used by the Rust verification implementation.
```bash
openssl rsa -in key.der \
            -inform DER \
            -RSAPublicKey_out \
            -outform DER \
            -out key.pub.der
```

Extract a public key from the private one in PEM representation to be used by the Node.js verification implementation.
```bash
openssl rsa -in key.pem \
            -inform PEM \
            -RSAPublicKey_out \
            -outform PEM \
            -out key.pub.pem
```

## Run the example

1. Sign the `data.txt` with the private key and create the `data.txt.sign` file by running the Rust sign implementation.

```bash
cargo run -- sign
```

_Note:_ This example already comes with `data.txt` and `data.txt.sign` files, but feel free to change the contents of the first one to verify the correct behavior of the implementations.

2. Verify the contents in `data.txt.sign` using the public key and the contents of `data.txt`. For this, one of the following options can be used:

   1. Run the Rust verification implementation under the `/rust` directory:

    ```bash
    cargo run -- verify
    ```

    2. Run the Node.js verification implementation under the `/ts` directory:

    ```bash
    npm start
    ```

