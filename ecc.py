from sympy import randprime
from random import randint
import time




def inverse_mod(k, p):
    return pow(k, -1, p)

def point_add(P1, P2, a, P):
    if P1 is None:
        return P2
    if P2 is None:
        return P1
    x1, y1 = P1
    x2, y2 = P2

    if x1 == x2 and (y1 + y2) % P == 0:
        return None  # Point at infinity

    if P1 != P2:
        s = ((y2 - y1) * inverse_mod(x2 - x1, P)) % P
    else:
        s = ((3 * x1 * x1 + a) * inverse_mod(2 * y1, P)) % P

    x3 = (s * s - x1 - x2) % P
    y3 = (s * (x1 - x3) - y1) % P

    return (x3, y3)

def scalar_mult(k, point, a, P):
    result = None
    addend = point

    while k:
        if k & 1:
            result = point_add(result, addend, a, P)
        addend = point_add(addend, addend, a, P)
        k >>= 1
    return result


def isQuardraticResidue(n, p):
    return pow(n, (p - 1) // 2, p) == 1

def tonelliShanksAlgorithm(n, p):
    #  checking the euler's criterion for p
    if isQuardraticResidue(n, p) == False:
        return None  # n is not a quadratic residue
    
   
    Q = p - 1
    S = 0
    while Q % 2 == 0:
        Q //= 2 # factoring out Q until Q is an odd number
        S += 1 # we need to multiply Q with 2 to the power s
    # we have a situation where p - 1 = Q * 2^s

    z = 2 # checking whether z is a quadratic residue, increasing the value of z until we find it
    while pow(z, (p - 1) // 2, p) != p - 1:
        z += 1
    
    
    M = S
    c = pow(z, Q, p)
    t = pow(n, Q, p)
    R = pow(n, (Q + 1) // 2, p)
    
    
    while True:
        if t == 0:
            return 0 # if t's value is 0, return 0
        if t == 1:
            return R #if t's value is 1, return R
        # otherwise we will use repeated squaring
        # to find the least i, 0 < i < M, such that t^(2^i) ≡ 1 mod p
        i = 0
        temp = t
        while temp != 1 and i < M:
            temp = pow(temp, 2, p) # to find the lowest i possible to ge the t^(2^i) ≡ 1 mod p
            i += 1
        if i == M:  # No solution exists, so return None
            return None
        b = pow(c, 2**(M - i - 1), p)
        M = i
        c = pow(b, 2, p)
        t = (t * c) % p
        R = (R * b) % p

def find_base_point(a, b, P):
    while True:
        x = randint(0, P-1)
        y_squared = (x**3 + a*x + b) % P

        # Euler's criterion: y² is a quadratic residue mod P
        if isQuardraticResidue(y_squared, P) == True:
            try:
                y = tonelliShanksAlgorithm(y_squared, P)
                return (x, y)
            except:
                continue  # If Tonelli–Shanks fails, try another x

def ecc(k):
    # Step 1: Generate curve parameters
    atime = 0
    btime = 0
    rtime = 0
    P = randprime(2 ** (k- 1), 2 ** (k))
    # print('randprime: ', P)
    a = randint(0, P-1)
    b = randint(0, P-1)
    while (4 * a**3 + 27 * b**2) % P == 0:
        a = randint(0, P-1)
        b = randint(0, P-1)

    # print('a, b: ', a, b)
    G = find_base_point(a, b, P)

    # geenrate a rendom key for Alice 
    start_time = time.perf_counter()
    Ka = randint(1, P-1)
    A = scalar_mult(Ka, G, a, P)
    end_time = time.perf_counter()
    # print('', end_time - start_time, 'ms', end=' : ')
    atime = end_time - start_time

    # Generate a random key for Bob
    start_time = time.perf_counter()
    Kb = randint(1, P-1)
    B = scalar_mult(Kb, G, a, P)
    end_time = time.perf_counter()
    # print('', end_time - start_time, 'ms' , end=' : ')
    btime = end_time - start_time

    start_time = time.perf_counter()
    #Alice get the bob's key B, and then calculating the shared key
    R_alice = scalar_mult(Ka, B, a, P)
    end_time = time.perf_counter()
    # print('', end_time - start_time, 'ms', end=' : ')
    rtime = end_time - start_time
    # Bob get the alice's key A, and then calculating the shared key
    R_bob = scalar_mult(Kb, A, a, P)

    assert R_alice == R_bob # Checking to make sure that both sides of the equation are equal so that alice and bob get the same key, otherwisre the algorithm is not working

    aes_key = R_alice[0].to_bytes((k + 7) // 8, 'big')[:k//8]
    # print("AES Key:", aes_key.hex())
    # print('AES Key length: ', aes_key)
    ans_key = ''
    for i in range(0, len(aes_key)):
        ans_key += chr(aes_key[i])
    # print('ANS Key: ', ans_key)
    # print(len(aes_key))
    return atime, btime, rtime
print('k  : computational time for a  : computation time for b  : shared key R' )
A128 = 0
B128 = 0
R128 = 0
A192 = 0
B192 = 0
R192 = 0
A256 = 0
B256 = 0
R256 = 0
round = 20
for i in range(0, round):
    tA128, tB128, tR128 = ecc(128)
    tA192, tB192, tR192 = ecc(192)
    tA256, tB256, tR256 = ecc(256)
    A128 += tA128
    B128 += tB128
    R128 += tR128
    A192 += tA192
    B192 += tB192
    R192 += tR192
    A256 += tA256
    B256 += tB256
    R256 += tR256


    # print('128 : ', tA128, ' : ', tB128, ' : ', tR128)
    # print('192 : ', tA192, ' : ', tB192, ' : ', tR192)
    # print('256 : ', tA256, ' : ', tB256, ' : ', tR256)
    # print(' ')
print('128 : ', A128/round, ' : ', B128/round, ' : ', R128/round)
print('192 : ', A192/round, ' : ', B192/round, ' : ', R192/round)
print('256 : ', A256/round, ' : ', B256/round, ' : ', R256/round)
print(' ')