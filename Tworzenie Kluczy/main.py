import base64

from Cryptodome.Cipher import AES
from Cryptodome.PublicKey import RSA
from Cryptodome.Random import get_random_bytes
import win32api
import win32file

def DetectUSB():
    #Znajdź USB
    drive_list = win32api.GetLogicalDriveStrings()
    drive_list = drive_list.split("\x00")[0:-1]  #Ostatni element to ""
    for letter in drive_list:
        if win32file.GetDriveType(letter) == win32file.DRIVE_REMOVABLE: #Sprawdź czy ostatni elemnt to USB
            print("Dysk USB to: " + str(letter))
            return letter
    return ""

def GenerateRSA():
    #Wygeneruj 4096 bitowy klucz RSA
    key = RSA.generate(4096)
    private_key = key.export_key()
    #with open("private.pem", "wb") as pub_file:
    #    pub_file.write(private_key)
    public_key = key.publickey().export_key()
    return private_key, public_key

def GeneratePin():
    #Wygeneruj 256 bitów (32 bajtów) PIN'u i wygeneruj cipher AES na jego podstawie
    pin = get_random_bytes(32)
    print("Twój pin do tego klucza RSA to: " + str(pin))
    return pin

def EncryptKey(pin, private_key):
    cipher = AES.new(pin, AES.MODE_OCB)
    ciphertext, tag = cipher.encrypt_and_digest(private_key)
    return cipher.nonce, tag, ciphertext

def ExportKey(nonce, tag, ciphertext):
    return base64.b64encode(nonce + tag + ciphertext).decode()

# Test
#def decrypt_private_key(encrypted_data, pin):
#    encrypted_bytes = base64.b64decode(encrypted_data)
#    nonce = encrypted_bytes[:15]  # OCB używa nonce o długości 15 bajtów
#    tag = encrypted_bytes[15:31]  # Tag ma 16 bajtów
#    ciphertext = encrypted_bytes[31:]
#
#    cipher = AES.new(pin, AES.MODE_OCB, nonce=nonce)
#    return cipher.decrypt_and_verify(ciphertext, tag)

# Test
#def save_decrypted_key_to_file(encrypted_data, pin, filename="decrypted_private.pem"):
#    decrypted_key = decrypt_private_key(encrypted_data, pin)
#    with open(filename, "wb") as file:
#        file.write(decrypted_key)
def SaveFiles(pin, exported_key, public_key, USB):
    # Zapis kluczy do plików
    with open("public.pem", "wb") as pub_file:
        pub_file.write(public_key)

    with open(USB+"encrypted_private.pem", "w") as priv_file:
        priv_file.write(exported_key)

    # Zapis PIN-u do pliku (UWAGA: PIN musi być przechowywany bezpiecznie!)
    with open("pin.bin", "wb") as pin_file:
        pin_file.write(pin)

USB = DetectUSB()
private_key, public_key = GenerateRSA()
pin = GeneratePin()
nonce, tag, ciphertext = EncryptKey(pin, private_key)
exported_key = ExportKey(nonce, tag, ciphertext)
SaveFiles(pin, exported_key, public_key, USB)
#save_decrypted_key_to_file(exported_key, pin)

