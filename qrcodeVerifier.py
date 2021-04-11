import qrtools
import argparse
import base64
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA256
from Crypto import Random
from Crypto.PublicKey import RSA

N = 344

def verifyData(data: str, filename: str, key_split: int):

    # reading key and verifying sign
    with open(filename, 'r') as f:
        # extract signature
        signature = base64.b64decode(data[:key_split])

        # import public key
        key = RSA.importKey(f.read())
        verifier = PKCS1_v1_5.new(key)

        try:
            # calculate hash
            # convert data to bytes
            data_bytes = base64.b64decode(data[key_split:])
            # get hash of data to sign
            hash = SHA256.new(data_bytes)
            return verifier.verify(hash, signature)
        except:
            return False

def decodeData(data: str, key_split: int):
    # convert data to bytes
    data_bytes = bytes(data[key_split:], 'utf-8')
    return base64.b64decode(data_bytes).decode()

def readQR(qrfile: str):
    qr = qrtools.QR()
    qr.decode(qrfile)
    return qr.data


if __name__ == "__main__":

    # use --help to get more info
    parser = argparse.ArgumentParser()
    parser.add_argument("--qr", default="qrcode.png", help="QRcode filename", type=str)
    parser.add_argument("--split", default=N, help="Split for signature", type=int)
    parser.add_argument("--publicKey", default="publicKey.pem", help="output filename for public key", type=str)
    args, other_args = parser.parse_known_args()

    # read QR code 
    data = readQR(args.qr)
    
    # verify data
    if (verifyData(data, args.publicKey, args.split)):
        print(f"[+] Verification Successful !")
        # if signature is valid
        decoded_data = decodeData(data, args.split)
        print(f"[+] Data: {decoded_data}")
    else:
        print("[-] Data corrupted, Validation Failed ! (Check for correct public Key)")