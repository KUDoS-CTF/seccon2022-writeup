from pwn import *
from Crypto.Util.number import *
import sys
from Crypto.Util.Padding import unpad
import time
from Crypto.Cipher import AES

#config
context(os='linux', arch='i386')
context.log_level = 'debug'

FILE_NAME = "./pseudo.py"

#"""
HOST = "witches-symmetric-exam.seccon.games"
PORT = 8080
"""
HOST = "localhost"
PORT = 7777
#"""

if len(sys.argv) > 1 and sys.argv[1] == 'r':
    conn = remote(HOST, PORT)
else:
    conn = process(["python3", FILE_NAME])


def send_oracle(payload):
    assert len(payload) % 16 == 0 and len(payload) >= 32

    _payload = payload.hex()
    _payload.zfill(len(payload) * 2)
    conn.sendlineafter(b': ', _payload.encode())
    resp = conn.recvline()
    if b'ofb error' in resp:
        return False
    else:
        return True

# padding oracle attack
# return palintext of c[-16:]
# (note: c includes IV)
def decrypt_ofb(c):
    # in aes-ofb, if IV is the same, then m[-16:] ^ c[-16:] = const.
    # "stack" stores this constant value
    stack = []
    for _ in range(16):
        for i in range(256):
            # change last 16 bytes (i.e., last block) into `\x00...\x00` + i + KNOWN_BYTES
            # KNOW_BYTES is computed based on "stack" so that the padding is appropriate
            payload = c[:-16]
            payload += b'\x00' * (15 - len(stack))
            payload += long_to_bytes(i)
            payload += b''.join([long_to_bytes(_ ^ (len(stack) + 1)) for _ in stack])    # KNOW_BYTES
            if send_oracle(payload):
                stack = [i ^ (len(stack) + 1)] + stack
                break
    
    # return (const.) ^ c[-16:]
    return b''.join([long_to_bytes(i ^ j) for i, j in zip(stack, c[-16:])])


c = int(conn.recvline().split(b': ')[1], 16)
c = long_to_bytes(c)

c_2 = unpad(decrypt_ofb(c), 16)
print('[+] c_2 analyze DONE')
time.sleep(3)

c_1 = decrypt_ofb(c[:64])
print('[+] c_1 analyze DONE')
time.sleep(3)

nonce = decrypt_ofb(c[:48])
print('[+] nonce analyze DONE')
time.sleep(3)
#tag = decrypt_ofb(c[:32])

# hash_subkey, i.e., E_k(0^128)
hash_subkey = decrypt_ofb(b'\x00' * 32)    
print('[+] hash_subkey calculate DONE')
time.sleep(3)

local = AES.new(os.urandom(16), AES.MODE_GCM, nonce=nonce)

# j0
ctr_0 = local.calculate_target_j0(hash_subkey)

ctr_1 = long_to_bytes(bytes_to_long(ctr_0) + 1)
ctr_2 = long_to_bytes(bytes_to_long(ctr_0) + 2)

# E_k(ctr_1) = m_1 ^ c_1
# E_k(ctr_2) = m_2 ^ c_2
m_1 = xor(decrypt_ofb(ctr_1 + b'\x00' * 16), c_1)
print('[+] secret_spell[:16] analyze DONE')
time.sleep(3)

m_2 = xor(decrypt_ofb(ctr_2 + b'\x00' * 16)[:8], c_2)
print('[+] secret_spell[16:] analyze DONE')

secret_spell = m_1 + m_2
print(f'secret_spell: {secret_spell}')
# decrypt_all!!277260221!!