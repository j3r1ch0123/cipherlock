#!/usr/bin/env python3
from Crypto.PublicKey import RSA
from cryptography.fernet import Fernet
from Crypto.Cipher import PKCS1_OAEP, AES
import base64
import os
import logging

# Handle errors and log them
logging.basicConfig(filename="error.log", level=logging.ERROR)

class Cipherlock():

    @staticmethod
    def generate_RSA_Key(key_size):
        # Create the keys
        try:
            thekey = RSA.generate(key_size)
            private_key = thekey.export_key()
            public_key = thekey.publickey().export_key()

            with open('private.pem', 'wb') as private:
                private.write(private_key)
                print("Private key generated...")

            with open('public.pem', 'wb') as public:
                public.write(public_key)
                print("Public key generated...")

            return (public_key, private_key)
        
        except Exception as e:
            print("Error generating key...")
            print(str(e))
            logging.error("Error:", exc_info=True)

            return None

    @staticmethod
    def generate_128_AES_Key():
        try:
            aeskey = Fernet.generate_key()
            with open('secret.pem', 'wb') as aes:
                aes.write(aeskey)
                print("AES Key generated...")
            
            return aeskey
        
        except Exception as e:
            print("Error generating key...")
            print(str(e))
            logging.error("Error:", exc_info=True)

            return None

    @staticmethod    
    def encrypt128AES(datafile, key):
        try:
            with open(datafile, "rb") as thefile:
                data = thefile.read()
                data_encrypted = Fernet(key).encrypt(data)
            
            return data_encrypted
        
        except Exception as e:
            print(f"Error generating keys...")
            print(str(e))
            logging.error("Error:", exc_info=True)

            return None
    
    @staticmethod
    def decrypt128AES(datafile, key):
        try:
            with open(datafile, "rb") as thefile:
                encrypted_data = thefile.read()
                decrypted_data = Fernet(key).decrypt(encrypted_data)
            
            return decrypted_data

        except Exception as e:
            print(f"Error generating keys...")
            print(str(e))
            logging.error("Error:", exc_info=True)

            return None

    @staticmethod
    def generate_256_AES_Key():
        aes_key = os.urandom(32)
        aes_key_encoded = base64.b64encode(aes_key)
        return aes_key_encoded
    
    @staticmethod
    def pad(data):
        padding_length = 16 - (len(data) % 16)
        padding = bytes([padding_length] * padding_length)
        return data + padding

    @staticmethod
    def unpad(data):
        padding_length = data[-1]
        return data[:-padding_length]
    
    @staticmethod
    def encrypt_256_AES(data, key):
        cipher = AES.new(key, AES.MODE_CBC)
        encrypted_data = cipher.encrypt(Cipherlock.pad(data))
        iv = base64.b64encode(cipher.iv).decode('utf-8')
        encrypted_data_base64 = base64.b64encode(encrypted_data).decode('utf-8')
        return iv, encrypted_data_base64

    @staticmethod
    def decrypt_256_AES(iv, data, key):
        cipher = AES.new(key, AES.MODE_CBC, iv=base64.b64decode(iv))
        decrypted_data = cipher.decrypt(base64.b64decode(data))
        return Cipherlock.unpad(decrypted_data)

    # Create encryption function
    @staticmethod
    def encryptRSA(datafile, publickey):
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
            
                return thefile
        
        except Exception as e:
            print(f"Error with encryption...")
            print(e)
            logging.error("Error", exc_info=True)

            return None
    
    # Create decryption function
    @staticmethod
    def decryptRSA(datafile, key):
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

            decryptedData = datafile

            return decryptedData
        
        except Exception as e:
            print("Error with decryption...")
            print(e)
            logging.error("Error:", exc_info=True)
            return None

    # Rotate keys for security purposes
    @staticmethod
    def rotate_2048_RSA_Keys(privKey, pubKey, data):
        try:
            decrypted_data = Cipherlock.decryptRSA(data, privKey)
            os.remove(privKey)
            os.remove(pubKey)

            new_key = Cipherlock.generate_2048_RSA_Key()
            encrypted_data = Cipherlock.encryptRSA(data, new_key)
            return (new_key, encrypted_data)

        except Exception as e:
            print("Error rotating keys...")
            print(str(e))
            logging.error("Error: ", exc_info=True)
            return None

    @staticmethod
    def rotate_4096_RSA_Keys(privKey, pubKey, data):
        try:
            decrypted_data = Cipherlock.decryptRSA(data, privKey)
            os.remove(privKey)
            os.remove(pubKey)

            new_key = Cipherlock.generate_4096_RSA_Key()
            encrypted_data = Cipherlock.encryptRSA(data, new_key)
            return (new_key, encrypted_data)

        except Exception as e:
            print("Error rotating keys...")
            print(str(e))
            logging.error("Error: ", exc_info=True)
            return None

    @staticmethod
    def rotate_128_AES_Key(secret_key, data):
        try:
            decrypted_data = Cipherlock.decrypt128AES(data, secret_key)
            os.remove(secret_key)
            new_key = Cipherlock.generate_AES_Key()
            encrypted_data = Cipherlock.encrypt128AES(data, new_key)
            return (new_key, encrypted_data)

        except Exception as e:
            print("Error rotating key...")
            print(str(e))
            logging.error("Error: ", exc_info=True)
            return None

    @staticmethod
    def rotate_256_AES_Key(secret_key, data):
        try:
            decrypted_data = Cipherlock.decrypt_256_AES(data['iv'], data['encrypted_data'], base64.b64decode(secret_key))
            new_key = Cipherlock.generate_256_AES_Key()
            iv, encrypted_data = Cipherlock.encrypt_256_AES(decrypted_data, base64.b64decode(new_key))

            return {
                'new_aes_key': new_key,
                'iv': iv,
                'encrypted_data': encrypted_data
            }
        
        except Exception as e:
            print("Error rotating key...")
            print(str(e))
            logging.error("Error: ", exc_info=True)

            return None