from ctypes import *
import os

dll_name = "randombytes.so"
dllabspath = os.path.dirname(os.path.abspath(__file__)) + os.path.sep + dll_name
CDLL(dllabspath, mode = RTLD_GLOBAL)

dll_name = "libpqcrystals_aes256ctr_ref.so"
dllabspath = os.path.dirname(os.path.abspath(__file__)) + os.path.sep + dll_name
CDLL(dllabspath, mode = RTLD_GLOBAL)

dll_name = "libpqcrystals_fips202_ref.so"
dllabspath = os.path.dirname(os.path.abspath(__file__)) + os.path.sep + dll_name
CDLL(dllabspath, mode = RTLD_GLOBAL)

dll_name = "libpqcrystals_dilithium3_ref.so"
dllabspath = os.path.dirname(os.path.abspath(__file__)) + os.path.sep + dll_name
dilithium = CDLL(dllabspath, mode = RTLD_GLOBAL)




PUBLIC_BYTES =  1952
PRIVATE_BYTES = 4016
BYTES = 3293

def string_to_ubyte_arr(message_string):
    message = (c_ubyte * (len(message_string)))()

    for i in range(len(message_string)):
        message[i] = c_ubyte(ord(message_string[i]))

    return message


def ubyte_arr_to_string(message_ubyte):
    message = ""
    for i in message_ubyte:
        message += chr(i)

    return message


def generate_keypair():
    public_key = (c_ubyte * PUBLIC_BYTES)()
    private_key = (c_ubyte * PRIVATE_BYTES)()

    dilithium.pqcrystals_dilithium3_ref_keypair(public_key, private_key)

    return public_key, private_key


def generate_signature(message, private_key):
    signature = (c_ubyte * BYTES)()
    signature_len = c_ulong(0)

    dilithium.pqcrystals_dilithium3_ref_signature(signature, byref(signature_len), message, c_ulong(len(message)), private_key)

    return signature, signature_len


def verify_signature(signature, siglen, message, public_key):
    return 0 == dilithium.pqcrystals_dilithium3_ref_verify(signature, siglen, message, c_ubyte(len(message)), public_key)


def encrypt_message(message, private_key):
    encrypted_message = (c_ubyte * (len(message) + BYTES))()
    encrypted_message_len = c_ulong(0)

    dilithium.pqcrystals_dilithium3_ref(encrypted_message, byref(encrypted_message_len), message, len(message), private_key)

    return encrypted_message, encrypted_message_len


def decrypt_message(encrypted_message, encrypted_message_length, public_key):
    message_extended = (c_ubyte * (BYTES))() # Poruka ne smije biti duža od BYTES
    message_len = c_ulong(0)
    
    dilithium.pqcrystals_dilithium3_ref_open(message_extended, byref(message_len), encrypted_message, encrypted_message_length, public_key)

    message = (c_ubyte * message_len.value)()
    for i in range(message_len.value):
        message[i] = message_extended[i]

    return message


#msg = string_to_ubyte_arr("Abvd")
#pk, sk = generate_keypair()
#sig, siglen = generate_signature(msg, sk)
#res = verify_signature(sig, siglen, msg, pk)

#emsg, emsglen = encrypt_message(msg, sk)
#dmsg = decrypt_message(emsg, emsglen, pk)
