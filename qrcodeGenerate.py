import qrcode
import argparse
import base64
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA256
from Crypto import Random
from Crypto.PublicKey import RSA

DATA = "This is test Data which goes into QRcode"
N = 2048
key_split = 344

def getMessage(raw_data: str, n: int, output_filename: str):

    # convert data to bytes
    data_bytes = bytes(raw_data, 'utf-8')
    # get hash of data to sign
    hash = SHA256.new(data_bytes)

    # generate Key and sign it
    key = RSA.generate(n)
    signer = PKCS1_v1_5.new(key)
    signature = signer.sign(hash)
    print(f"[+] Data Signed")

    # save public key to give it to verifier
    pubKey = key.publickey()
    with open(output_filename, 'w') as f:
        f.write(pubKey.exportKey('PEM').decode())
        print(f"[+] Public Key exported to '{output_filename}'")

    # concatenate signature and message 
    final_data = base64.b64encode(signature) + base64.b64encode(data_bytes)
    return final_data.decode()


def createQR(msg: str, filename: str):
    # create qrcode config
    qr = qrcode.QRCode(
        version=None,
        error_correction=qrcode.constants.ERROR_CORRECT_H,
        box_size=10,
        border=4,
    )

    qr.add_data(msg)
    qr.make(fit=True)

    img = qr.make_image(fill_color="black", back_color="white")
    img.save(filename)
    print(f"[+] QR code saved in '{filename}'")

if __name__ == "__main__":

    # use --help to get more info
    parser = argparse.ArgumentParser()
    parser.add_argument("--data", default=DATA, help="Content for QRcode", type=str)
    parser.add_argument("--n", default=N, help="Key Length for RSA", type=int)
    parser.add_argument("--publicKey", default="publicKey.pem", help="output filename for public key", type=str)
    parser.add_argument("--output", default="qrcode.png", help="output filename for qrcode", type=str)
    args, other_args = parser.parse_known_args()

    # get messgage data and save public key
    data = getMessage(args.data, args.n, args.publicKey)

    # create qrcode
    createQR(data, args.output)

    print(f"[+] Final Data : {data}")

    




