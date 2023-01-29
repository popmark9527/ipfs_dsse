from random import random

from Cryptodome.Cipher import AES
import operator

AES_BLOCK_SIZE = AES.block_size
AES_KEY_SIZE = 16
def PadTest(bytes):
    while len(bytes) % AES_BLOCK_SIZE != 0:
        bytes += ' '.encode()
    return bytes
def PadKey(key):
    if len(key) > AES_KEY_SIZE:
        return key[:AES_KEY_SIZE]
    while len(key) % AES_KEY_SIZE != 0:
        key += ' '.encode()
    return key


def EnCrypt(key, bytes):
    myCipher = AES.new(key, AES.MODE_ECB)
    encryptData = myCipher.encrypt(bytes)
    return encryptData

def DeCrypt(key, encryptData):
    myCipher = AES.new(key, AES.MODE_ECB)
    bytes = myCipher.decrypt(encryptData)
    return bytes
def filehash(id_str):
    return hash(id_str)

def f(key, bytes):
    key = PadKey(key)
    bytes = PadTest(bytes)
    return EnCrypt(key, bytes)

def randomStr(num):
    seed = "1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!@#$%^&*()_+=-"
    str1 = []
    for i in range(num):
        str1.append(random.choice(seed))
    StringS = ''.join(str1)
    return StringS



