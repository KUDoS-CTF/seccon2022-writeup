from pwn import *
from Crypto.Util.number import *
import sys
import gmpy2

#config
context(os='linux', arch='i386')
context.log_level = 'debug'

FILE_NAME = "./pseudo.py"

#"""
HOST = "BBB.seccon.games"
PORT = 8080
"""
HOST = "localhost"
PORT = 7777
#"""

# solve x^2 + Ax + B = target mod p
def find_seed(target):
    PR.<x> = PolynomialRing(GF(p))
    f = x**2 + a * x + b - target
    res = f.roots()
    if len(res) != 0:
        return [res[0][0], res[1][0]], True
    else:
        return [], False

while True:    
    if len(sys.argv) > 1 and sys.argv[1] == 'r':
        conn = remote(HOST, PORT)
    else:
        conn = process(["python3", FILE_NAME])

    conn.recvline()
    a = eval(conn.recvline().split(b'=')[1])
    p = eval(conn.recvline().split(b'=')[1])

    e = 11
    # set backdoor B
    b = (- e**2 - a * e + e) % p
    conn.sendlineafter(b': ', str(b).encode())


    # find f(x) = e
    # always x=11 is a solution
    x_ls, flag = find_seed(e)
    assert flag and 11 in x_ls
    x_1, x_2 = x_ls
    # fix x_1 = 11
    if x_2 == 11:
        x_1, x_2 = x_2, x_1
    print('[+] x_1 and x_2 ok')

    # find f(f(x)) = e, i.e., f(x) = x_2
    # solution does not always exist
    x_ls, flag = find_seed(x_2)
    if not flag:
        print('[-] x_3 and x_4 not found. retry')
        conn.close()
        continue
    x_3, x_4 = x_ls
    print('[+] x_3 and x_4 ok')

    # find f(f(f(x))) = e, i.e., f(x) = x_3/x_4
    x_ls, flag = find_seed(x_3)
    if not flag:
        x_ls, flag = find_seed(x_4)
        if not flag:
            print('[-] x_5 not found. retry')
            conn.close()
            continue
    x_5 = x_ls[0]
    print('[+] x_5 ok')

    

    if (len(set([x_1, x_2, x_3, x_4, x_5]))) != 5:
        print('[-] seed dupulicates. retry')
        conn.close()
        continue

    conn.sendlineafter(b': ', str(x_1).encode())
    conn.sendlineafter(b': ', str(x_2).encode())
    conn.sendlineafter(b': ', str(x_3).encode())
    conn.sendlineafter(b': ', str(x_4).encode())
    conn.sendlineafter(b': ', str(x_5).encode())

    # hastad broadcast attack
    n_list = []
    e_list = []
    c_list = []
    for i in range(5):
        conn.recvline()
        n = eval(conn.recvline().split(b'=')[1])
        n_list.append(n)
        e = eval(conn.recvline().split(b'=')[1])
        e_list.append(e)
        c = eval(conn.recvline().split(b': ')[1])
        c_list.append(c)
    assert e_list == [11, 11, 11, 11, 11]
    
    c = crt(c_list, n_list)
    m, flag = gmpy2.iroot(int(c), 11)
    assert flag
    print(long_to_bytes(int(m)))
    # SECCON{Can_you_find_d_in_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbdbbbbbbbbbbbbbbbbbbbbbbbbbbbbb?}
    conn.close()
    break
