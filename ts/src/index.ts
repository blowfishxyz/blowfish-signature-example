import * as fs from 'fs'
import * as crypto from 'crypto'

const PRIVATE_KEY_PEM_PATH = '../data/key.pem'
const PUBLIC_KEY_PEM_PATH = '../data/key.pub.pem'

const MESSAGE_FILE_PATH = '../data/data.txt'
const SIGNATURE_FILE_PATH = '../data/data.txt.sign'

const privateKey = fs.readFileSync(PRIVATE_KEY_PEM_PATH, 'utf-8')
const publicKey = fs.readFileSync(PUBLIC_KEY_PEM_PATH, 'utf-8')

function validateDigitalSignature(data: string, receivedSignature: string): boolean {
  const verify = crypto.createVerify('RSA-SHA256')
  verify.update(data, 'binary')
  return verify.verify(publicKey, receivedSignature, 'binary')
}

export function main() {
  // Read message from data file
  const message = fs.readFileSync(MESSAGE_FILE_PATH, 'utf-8')

  // Read digital signature
  const signatureHex = fs.readFileSync(SIGNATURE_FILE_PATH, 'binary')
  const signature = Buffer.from(signatureHex, 'hex').toString('binary')

  // Validate the digital signature
  const isSignatureValid = validateDigitalSignature(message, signature)
  console.log('Signature Validation Result:', isSignatureValid)
}

main()
