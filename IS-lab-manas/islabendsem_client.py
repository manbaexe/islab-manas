import socket
import random
import hashlib
from hashlib import sha256
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from sympy import isprime


def generate_rsa_keypair(bits=2048):
    key = RSA.generate(bits)
    private_key = key
    public_key = key.publickey()
    return public_key, private_key


def rsa_encrypt(public_key, message):
    cipher = PKCS1_OAEP.new(public_key)
    ciphertext = cipher.encrypt(message)
    return ciphertext


def md5_hash(input_string):
    # Create an MD5 hash object
    md5_hash_object = hashlib.md5()
    # Update the hash object with the input string only (no need to do .encode() as the file was read in rb)
    md5_hash_object.update(input_string)
    # Get the hexadecimal representation of the hash
    md5_digest = md5_hash_object.hexdigest()

    return md5_digest


def generate_prime(bit_length=256):
    # Generate a random prime of specified bit length
    while True:
        p = random.getrandbits(bit_length)
        if isprime(p):
            return p


def generate_keys(bit_length=256):
    p = generate_prime(bit_length)
    g = random.randint(2, p - 2)
    x = random.randint(1, p - 2)
    y = pow(g, x, p)
    return p, g, x, y


def hash_message(message):
    # If message is in bytes, use it directly; otherwise, encode as bytes
    if not isinstance(message, bytes):
        message = message.encode('utf-8')
    return int(sha256(message).hexdigest(), 16)


def gcd(a, b):
    while b:
        a, b = b, a % b
    return a


def mod_inverse(a, m):
    # Compute modular inverse of a under modulus m
    if gcd(a, m) != 1:
        raise ValueError("Inverse does not exist")
    return pow(a, -1, m)


def sign_message(message, p, g, x):
    h = hash_message(message) % p
    while True:
        k = random.randint(1, p - 2)
        if gcd(k, p - 1) == 1:
            break
    r = pow(g, k, p)
    k_inv = mod_inverse(k, p - 1)
    s = (k_inv * (h - x * r)) % (p - 1)
    return r, s


def start_client(file_path):
    # Create TCP socket
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # Connect to server's address and port
    client_socket.connect(("localhost", 12345))

    try:
        # Receive the public key from the server
        public_key_data = client_socket.recv(4096)  # Buffer size for the public key
        public_key = RSA.import_key(public_key_data)
        print("Public Key Received")

        # Read the file content in binary mode
        with open(file_path, 'rb') as file:
            file_data = file.read()

        # Encrypt the file content using the received public key
        encrypted_file_data = rsa_encrypt(public_key, file_data)
        # Send the encrypted file content to the server
        client_socket.sendall(encrypted_file_data)
        print("Encrypted file content sent to the server.")

        # Sending Hashed Message
        hashed_message = md5_hash(file_data)
        client_socket.sendall(hashed_message.encode())
        print("Hashed Message Sent To Server")

        # ElGamal Signature
        p, g, x, y = generate_keys()
        r, s = sign_message(file_data, p, g, x)  # File data is hashed and signed
        print(f"Signature (r, s): ({r}, {s})")

        # Send the ElGamal public key parameters
        sign_keys = f"{p},{g},{y}".encode()  # Send p, g, and y (public key)
        client_socket.sendall(sign_keys)
        print("Signature Keys Sent")

        # Convert the signature (r, s) into a string, encode to bytes, and send
        signature = f"{r},{s}".encode()
        client_socket.sendall(signature)
        print("Signature (r, s) sent to the server.")

    finally:
        client_socket.close()


# Run the client function
if __name__ == "__main__":
    # Path to the text file to be sent
    file_path = "D:\\pythonprojectpratcieendsemis\\message.txt"
    start_client(file_path)