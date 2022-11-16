from pwn import *
from Crypto.Util.number import *
import sys

#config
context(os='linux', arch='i386')
context.log_level = 'debug'

FILE_NAME = "./pseudo.py"

#"""
HOST = "this-is-not-lsb.seccon.games"
PORT = 8080
"""
HOST = "localhost"
PORT = 7777
#"""

if len(sys.argv) > 1 and sys.argv[1] == 'r':
    conn = remote(HOST, PORT)
else:
    conn = process(["python3", FILE_NAME])


n = eval(conn.recvline().split(b' = ')[1])
assert n.bit_length() == 1024

e = eval(conn.recvline().split(b' = ')[1])
assert e == 65537

flag_length = eval(conn.recvline().split(b' = ')[1])
assert flag_length == 439

c = eval(conn.recvline().split(b' = ')[1])


def send_oracle(payload:int):
    conn.sendlineafter(b'c = ', str(payload).encode())
    resp = conn.recvline()
    if b'True' in resp:
        return True
    elif b'False' in resp:
        return False
    else:
        print('[-] coding error')
        assert 1==2
        return False

# find k_min such that
# (k_min - 1) * m <  0b00_1111_1111_0000...
#  k_min      * m >= 0b00_1111_1111_0000...
_min = (49 * 2**577)
_max = (49 * 2**578)

while _max - _min > 1:
    _mid = (_min + _max) // 2
    if send_oracle(c * pow(_mid, e, n) % n):
        _max = _mid
    else:
        _min = _mid
    print(f'[*] diff: {_max - _min}')

assert _max - _min == 1
assert send_oracle(c * pow(_max, e, n) % n)
assert not send_oracle( c * pow(_min, e, n) % n)
k_min = _max
val_min = (0xFF << 1014) 

# find k_max such that
#  k_max      * m <= 0b00_1111_1111_1111...
# (k_max + 1) * m >  0b00_1111_1111_1111...
_min = (49 * 2**578)
_max = (49 * 2**579)

while _max - _min > 1:
    _mid = (_min + _max) // 2
    if send_oracle(c * pow(_mid, e, n) % n):
        _min = _mid
    else:
        _max = _mid
    print(f'[*] diff: {_max - _min}')

assert _max - _min == 1
assert send_oracle(c * pow(_min, e, n) % n)
assert not send_oracle(c * pow(_max, e, n) % n)
k_max = _min
val_max = (0x100 << 1014) - 1

conn.close()
print(long_to_bytes(val_min // k_min))
print(long_to_bytes(val_max // k_max))
# SECCON{WeLC0me_t0_tHe_MirRoR_LaNd!_tHIs_is_lSb_orAcLe!}
