import base64
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
import win32api
import win32file
import getpass

def DetectUSB():
    # Find USB drive
    drive_list = win32api.GetLogicalDriveStrings()
    drive_list = drive_list.split("\x00")[0:-1]  # Last element is ""
    for letter in drive_list:
        if win32file.GetDriveType(letter) == win32file.DRIVE_REMOVABLE: # Check if it's a removable drive
            print("USB drive found: " + str(letter))
            return letter
    return ""

def GenerateRSA():
    # Generate 4096-bit RSA key
    key = RSA.generate(4096)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key

def GetUserPin():
    # Get PIN from user and ensure it's 32 bytes long
    while True:
        pin = getpass.getpass("Enter your PIN (will be used to encrypt your private key): ")
        if len(pin) < 8:
            print("PIN must be at least 8 characters long")
            continue
        
        # Convert PIN to 32 bytes using SHA-256 hash if it's too short
        if len(pin) < 32:
            from Crypto.Hash import SHA256
            pin_hash = SHA256.new(pin.encode()).digest()
            print(f"Note: Your PIN has been hashed to 32 bytes for encryption")
            return pin_hash
        elif len(pin) > 32:
            print("Warning: PIN is longer than 32 bytes, it will be truncated")
            return pin.encode()[:32]
        else:
            return pin.encode()

def EncryptKey(pin, private_key):
    cipher = AES.new(pin, AES.MODE_OCB)
    ciphertext, tag = cipher.encrypt_and_digest(private_key)
    return cipher.nonce, tag, ciphertext

def ExportKey(nonce, tag, ciphertext):
    return base64.b64encode(nonce + tag + ciphertext).decode()

def SaveFiles(pin, exported_key, public_key, USB):
    # Save public key to file
    with open("public.pem", "wb") as pub_file:
        pub_file.write(public_key)

    # Save encrypted private key to USB drive
    if USB:
        with open(USB+"encrypted_private.pem", "w") as priv_file:
            priv_file.write(exported_key)
        print(f"Encrypted private key saved to USB drive: {USB}encrypted_private.pem")
    else:
        print("Warning: No USB drive found, saving encrypted private key locally")
        with open("encrypted_private.pem", "w") as priv_file:
            priv_file.write(exported_key)

    print("Public key saved to: public.pem")
    print("IMPORTANT: Remember your PIN as it's needed to decrypt the private key")
    print("The PIN is NOT stored anywhere for security reasons")

def main():
    print("RSA Key Pair Generator with PIN Protection")
    print("-----------------------------------------")
    
    USB = DetectUSB()
    private_key, public_key = GenerateRSA()
    pin = GetUserPin()
    nonce, tag, ciphertext = EncryptKey(pin, private_key)
    exported_key = ExportKey(nonce, tag, ciphertext)
    SaveFiles(pin, exported_key, public_key, USB)

if __name__ == "__main__":
    main()