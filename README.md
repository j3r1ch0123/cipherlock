# Cipherlock Python Cryptography Module Documentation

The `Cipherlock` module is a Python cryptography library that provides various functions for encrypting and decrypting data using both RSA and AES encryption algorithms. It also includes key generation and key rotation features to enhance security. Below is the documentation for the `Cipherlock` module, explaining its functions and usage. 256 AES encryption is still a work in progress, but RSA should work just fine.

## Table of Contents
1. [Installation](#installation)
2. [Key Generation](#key-generation)
    - [generate_RSA_Key(key_size)](#generate_rsa_keykey_size)
    - [generate_128_AES_Key()](#generate_128_aes_key)
    - [generate_256_AES_Key()](#generate_256_aes_key)
3. [AES Encryption and Decryption](#aes-encryption-and-decryption)
    - [encrypt128AES(datafile, key)](#encrypt128aesdatafile-key)
    - [decrypt128AES(datafile, key)](#decrypt128aesdatafile-key)
    - [encrypt_256_AES(data, key)](#encrypt_256_aesdata-key)
    - [decrypt_256_AES(iv, data, key)](#decrypt_256_aesiv-data-key)
4. [RSA Encryption and Decryption](#rsa-encryption-and-decryption)
    - [encryptRSA(datafile, publickey)](#encryptrsadatafile-publickey)
    - [decryptRSA(datafile, key)](#decryptrsadatafile-key)
5. [Key Rotation](#key-rotation)
    - [rotate_2048_RSA_Keys(privKey, pubKey, data)](#rotate_2048_rsa_keysprivkey-pubkey-data)
    - [rotate_4096_RSA_Keys(privKey, pubKey, data)](#rotate_4096_rsa_keysprivkey-pubkey-data)
    - [rotate_128_AES_Key(secret_key, data)](#rotate_128_aes_keysecret_key-data)
    - [rotate_256_AES_Key(secret_key, data)](#rotate_256_aes_keysecret_key-data)

### Installation <a name="installation"></a>

Before using the `Cipherlock` module, you need to make sure you have the required Python libraries installed. You can install them using pip:

```bash
pip install pycryptodome cryptography
```

### Key Generation <a name="key-generation"></a>

#### generate_RSA_Key(key_size) <a name="generate_rsa_keykey_size"></a>
This function generates an RSA key pair and saves them to 'private.pem' and 'public.pem' files. It returns the public and private keys.

```python
public_key, private_key = Cipherlock.generate_RSA_Key(key_size)
```

#### generate_128_AES_Key() <a name="generate_128_aes_key"></a>
This function generates a 128-bit AES key and saves it to a 'secret.pem' file. It returns the generated AES key.

```python
aes_key = Cipherlock.generate_128_AES_Key()
```

#### generate_256_AES_Key() <a name="generate_256_aes_key"></a>
This function generates a 256-bit AES key and returns it as a base64 encoded string.

```python
aes_key = Cipherlock.generate_256_AES_Key()
```

### AES Encryption and Decryption <a name="aes-encryption-and-decryption"></a>

#### encrypt128AES(datafile, key) <a name="encrypt128aesdatafile-key"></a>
Encrypts data from the specified file using a 128-bit AES key. It returns the encrypted data as bytes.

```python
encrypted_data = Cipherlock.encrypt128AES(datafile, key)
```

#### decrypt128AES(datafile, key) <a name="decrypt128aesdatafile-key"></a>
Decrypts data from the specified file using a 128-bit AES key. It returns the decrypted data as bytes.

```python
decrypted_data = Cipherlock.decrypt128AES(datafile, key)
```

#### encrypt_256_AES(data, key) <a name="encrypt_256_aesdata-key"></a>
Encrypts data using a 256-bit AES key. It returns an initialization vector (IV) and the encrypted data as base64-encoded strings.

```python
iv, encrypted_data = Cipherlock.encrypt_256_AES(data, key)
```

#### decrypt_256_AES(iv, data, key) <a name="decrypt_256_aesiv-data-key"></a>
Decrypts data using a 256-bit AES key and the provided initialization vector (IV). It returns the decrypted data as bytes.

```python
decrypted_data = Cipherlock.decrypt_256_AES(iv, data, key)
```

### RSA Encryption and Decryption <a name="rsa-encryption-and-decryption"></a>

#### encryptRSA(datafile, publickey) <a name="encryptrsadatafile-publickey"></a>
Encrypts the data from a file using RSA encryption with the provided public key. It returns the path to the encrypted file.

```python
encrypted_file = Cipherlock.encryptRSA(datafile, publickey)
```

#### decryptRSA(datafile, key) <a name="decryptrsadatafile-key"></a>
Decrypts an RSA-encrypted file using the provided private key. It returns the path to the decrypted file.

```python
decrypted_file = Cipherlock.decryptRSA(datafile, key)
```

### Key Rotation <a name="key-rotation"></a>

Key rotation functions allow you to replace existing keys with new ones for improved security.

#### rotate_2048_RSA_Keys(privKey, pubKey, data) <a name="rotate_2048_rsa_keysprivkey-pubkey-data"></a>
Rotates RSA keys by decrypting data with the existing private key, removing the old keys, generating new 2048-bit RSA keys, and encrypting the data with the new public key. Returns the new public key and the encrypted data.

```python
new_public_key, encrypted_data = Cipherlock.rotate_2048_RSA_Keys(privKey, pubKey, data)
```

#### rotate_4096_RSA_Keys(privKey, pubKey, data) <a name="rotate_4096_rsa_keysprivkey-pubkey-data"></a>
Similar to the previous function but rotates RSA keys with new 4096-bit keys.

```python
new_public_key, encrypted_data = Cipherlock.rotate_4096_RSA_Keys(privKey, pubKey, data)
```

#### rotate_128_AES_Key(secret_key, data) <a name="rotate_128_aes_keysecret_key-data"></a>
Rotates a 128-bit AES key by decrypting data with the existing key, removing the old key, generating a new AES key, and encrypting the data with the new key. Returns the new key and the encrypted data.

```python
new_aes_key, encrypted_data = Cipherlock.rotate_128_AES_Key(secret_key, data)
```

#### rotate_256_AES_Key(secret_key, data) <a name="rotate_256_aes_keysecret_key-data"></a>
Rotates a 256-bit AES key by decrypting data with the existing key, generating a new AES key, and encrypting the data with the new key. Returns the new key, IV, and the encrypted data.

```python
new_aes_key, iv, encrypted_data = Cipherlock.rotate_256_AES_Key(secret_key, data)
```

This documentation provides an overview of the `Cipherlock` module
