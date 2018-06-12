from Cryptodome.PublicKey import RSA
from Cryptodome.Random import get_random_bytes
from Cryptodome.Cipher import AES, PKCS1_OAEP


def gen_rsa_key(passphrase="Unguessable", raskey_filepath="rsa.key"):
    key = RSA.generate(2048)
    encrypted_key = key.exportKey(passphrase=passphrase, pkcs=8,
                                  protection="scryptAndAES128-CBC")
    file_out = open(raskey_filepath, "wb")
    file_out.write(encrypted_key)
    return key


def encrypt_data(data_filepath='encrypted.data', raskey_filepath='rsa.key', passphrase='Unguessable', data='string_data'):
    file_out = open(data_filepath, "wb")
    encoded_key = open(raskey_filepath, "rb").read()
    recipient_key = RSA.import_key(encoded_key, passphrase=passphrase)
    session_key = get_random_bytes(16)
    cipher_rsa = PKCS1_OAEP.new(recipient_key)
    file_out.write(cipher_rsa.encrypt(session_key))
    cipher_aes = AES.new(session_key, AES.MODE_EAX)
    byte_data = data.encode('utf-8')
    ciphertext, tag = cipher_aes.encrypt_and_digest(byte_data)
    [file_out.write(x) for x in (cipher_aes.nonce, tag, ciphertext)]


def decrypt_data(data_filepath='encrypted.data', raskey_filepath='rsa.key', passphrase='Unguessable'):
    file_in = open(data_filepath, "rb")
    encoded_key = open(raskey_filepath, "rb").read()
    private_key = RSA.import_key(encoded_key, passphrase=passphrase)
    enc_session_key, nonce, tag, ciphertext = \
        [file_in.read(x) for x in (private_key.size_in_bytes(), 16, 16, -1)]
    cipher_rsa = PKCS1_OAEP.new(private_key)
    session_key = cipher_rsa.decrypt(enc_session_key)
    cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
    data = cipher_aes.decrypt_and_verify(ciphertext, tag)
    string_data = data.decode('utf-8')
    return string_data
