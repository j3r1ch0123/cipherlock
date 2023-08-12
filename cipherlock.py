#!/bin/python3.9
from Crypto.PublicKey import RSA
from cryptography.fernet import Fernet
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
import os
import logging

# Handle errors and log them
logging.basicConfig(filename="error.log", level=logging.ERROR)

class Cipherlock():

    def generate_key():
        # Create the keys
        try:
            thekey = RSA.generate(2048)
            private_key = thekey.export_key()
            public_key = thekey.publickey().export_key()

            with open('private.pem', 'wb') as private:
                private.write(private_key)
                print("Private key generated...")

            with open('public.pem', 'wb') as public:
                public.write(public_key)
                print("Public key generated...")

            # Generate AES key
            aeskey = Fernet.generate_key()
            with open('secret.pem', 'wb') as aes:
                encrypted_key = encrypt('secret.pem', public_key)
                aes.write(encrypted_key)
                print("Hybrid Key generated...")
        
        except Exception as e:
            print(f"Error generating keys...")
            print(str(e))
            logging.error("Error:", exc_info=True)
    
    # Return hybrid key to AES key for decryption
    def decrypt_hybrid_key(hybrid_key, privKey):
        try:
            with open(privKey, "rb") as privateKey:
                if os.path.exists(privKey):
                    privateKey = RSA.import_key(privateKey.read())
                else:
                    print("Key not found...")
                    return None
            
            key = privateKey.decrypt(hybrid_key)

            return hybrid_key
        
        except Exception as e:
            print(f"Error decrypting key...")
            print(e)
            logging.error("Error:", exc_info=True)

            return None

    # Create encryption function
    def encrypt(datafile, publickey):
        try:
            if not os.path.exists(datafile):
                raise ValueError("Datafile not found...")
            
            if not os.path.isfile(datafile):
                raise ValueError("Datafile path not a file...")

            datafile = str(datafile)
            with open(datafile, "rb") as f:
                data = f.read()

            data = bytes(data)

            key = RSA.import_key(publickey)
            sessionkey = os.urandom(16)

            cipher = PKCS1_OAEP.new(key)
            encryptedSessionKey = cipher.encrypt(sessionkey)

            cipher = AES.new(sessionkey, AES.MODE_EAX)
            ciphertext, tag = cipher.encrypt_and_digest(data)

            encryptedFile = datafile
            with open(encryptedFile, "wb") as thefile:
                [ thefile.write(x) for x in (encryptedSessionKey, cipher.nonce, tag, ciphertext) ]
        
        except Exception as e:
            print(f"Error with encryption...")
            print(e)
            logging.error("Error", exc_info=True)
    
    # Create decryption function
    def decrypt(datafile, key):
        try:
            if not os.path.exists(datafile):
                raise ValueError("Datafile not found...")
            
            if not os.path.isfile(datafile):
                raise ValueError("Datafile path is not a file...")
            with open(key, "rb") as thekey:
                decryption_key = thekey.read()
            
            with open(datafile, "rb") as thefile:
                encryptedSessionKey, nonce, tag, ciphertext = [ thefile.read(x) for x in (256, 16, 16, -1) ]
            
            private_key = RSA.import_key(decryption_key)
            cipher = PKCS1_OAEP.new(private_key)
            sessionKey = cipher.decrypt(encryptedSessionKey)

            cipher = AES.new(sessionKey, AES.MODE_EAX, nonce)
            data = cipher.decrypt_and_verify(ciphertext, tag)

            decryptedFile = datafile
            with open(decryptedFile, "wb") as thefile:
                thefile.write(data)
                print("File decrypted...")
        
        except Exception as e:
            print("Error with decryption...")
            print(e)
            logging.error("Error:", exc_info=True)
