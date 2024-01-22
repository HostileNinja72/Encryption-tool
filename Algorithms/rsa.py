# Algorithms/rsa.py
import random
from sympy import isprime, mod_inverse

class RSA:
    @staticmethod
    def generate_prime_candidate(length):
        p = random.getrandbits(length)
        p |= (1 << length - 1) | 1
        return p

    @staticmethod
    def generate_prime_number(length=1024):
        p = 4
        while not isprime(p):
            p = RSA.generate_prime_candidate(length)
        return p

    @staticmethod
    def gcd(a, b):
        while b != 0:
            a, b = b, a % b
        return a

    @staticmethod
    def generate_keys(length=1024):
        p = RSA.generate_prime_number(length)
        q = RSA.generate_prime_number(length)
        n = p * q
        phi = (p - 1) * (q - 1)

        e = random.randrange(1, phi)
        g = RSA.gcd(e, phi)
        while g != 1:
            e = random.randrange(1, phi)
            g = RSA.gcd(e, phi)

        d = mod_inverse(e, phi)
        return ((e, n), (d, n))

    @staticmethod
    def encrypt(pk, plaintext):
        key, n = pk
        return [pow(ord(char), key, n) for char in plaintext]

    @staticmethod
    def decrypt(pk, ciphertext):
        key, n = pk
        return ''.join([chr(pow(char, key, n)) for char in ciphertext])
