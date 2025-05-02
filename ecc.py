from sympy import randprime, mod_inverse
from random import randint
import time

# Step 1: Generate curve parameters
k = 128  # AES-128
P = randprime(2**(k-1), 2**k)  # k-bit prime

# Random curve parameters (a, b)
a, b = randint(0, P-1), randint(0, P-1)
while (4 * a**3 + 27 * b**2) % P == 0:  # Check non-singular
    a, b = randint(0, P-1), randint(0, P-1)



def is_quadratic_residue(x, P):
    # Euler's criterion: Is x a quadratic residue mod P?
    return pow(x, (P - 1) // 2, P) == 1

# Step 2: Find base point G (x, y) on the curve y² ≡ x³ + ax + b mod P
def tonelli_shanks(n, p):
    
    pass

x = randint(0, P-1)
y_squared = (x**3 + a*x + b) % P
y = tonelli_shanks(y_squared, P)  # Assume implemented
G = (x, y)

# Step 3: Key exchange
Ka = randint(1, P-1)  # Alice's private key
A = (Ka * G[0] % P, Ka * G[1] % P)  # Public key

Kb = randint(1, P-1)  # Bob's private key
B = (Kb * G[0] % P, Kb * G[1] % P)  # Public key

# Step 4: Shared secret (x-coordinate as AES key)
R_alice = (Ka * B[0] % P, Ka * B[1] % P)
R_bob = (Kb * A[0] % P, Kb * A[1] % P)
assert R_alice == R_bob  # Verify correctness

aes_key = R_alice[0].to_bytes((k + 7) // 8, 'big')[:k//8]
print("AES Key:", aes_key.hex())