import socket
import hashlib
from hashlib import sha256
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

def generate_rsa_keypair(bits=2048):
    key = RSA.generate(bits)
    private_key = key
    public_key = key.publickey()
    return public_key, private_key

def rsa_decrypt(private_key, ciphertext):
    cipher = PKCS1_OAEP.new(private_key)
    decrypted_message = cipher.decrypt(ciphertext)
    return decrypted_message

def md5_hash(input_data):
    md5_hash_object = hashlib.md5()
    md5_hash_object.update(input_data)
    return md5_hash_object.hexdigest().encode('utf-8')

public_key, private_key = generate_rsa_keypair()

def hash_message(message):
    # If message is in bytes, use it directly; otherwise, encode as bytes
    if not isinstance(message, bytes):
        message = message.encode('utf-8')
    return int(sha256(message).hexdigest(), 16)

def verify_signature(message, r, s, p, g, y):
    if not (0 < r < p and 0 <= s < p - 1):
        return False
    h = hash_message(message) % p
    v1 = pow(g, h, p)
    v2 = (pow(y, r, p) * pow(r, s, p)) % p
    return v1 == v2

def start_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(("localhost", 12345))
    server_socket.listen(1)
    print("Server is listening on port 12345...")

    while True:
        client_socket, addr = server_socket.accept()
        try:
            print(f"Connected to client: {addr}")

            # Send the public key to the client
            public_key_data = public_key.export_key()
            client_socket.sendall(public_key_data)
            print("Public key sent to client.")

            # Receive encrypted data from the client
            encrypted_data = client_socket.recv(256)

            # Receive the hash from the client after the encrypted content
            received_hash = client_socket.recv(64)

            # Decrypt the received message
            decrypted_message = rsa_decrypt(private_key, encrypted_data)
            print(f"Decrypted message: {decrypted_message.decode()}")

            # Compute the hash of the decrypted message to verify integrity
            local_hash = md5_hash(decrypted_message)
            print("Local Hash: ", local_hash)
            print("Received Hash: ", received_hash)

            # Compare the received hash with the locally computed hash
            if received_hash == local_hash:
                print("Data integrity verified: No tampering detected.")
            else:
                print("Data integrity verification failed: Data may be corrupted or tampered with.")

            # Receive the ElGamal keys (p, g, x)
            sign_keys = client_socket.recv(1024)  # Adjust buffer size as needed
            decoded_keys = sign_keys.decode()

            # Debugging: Print the received keys
            print(f"Received ElGamal keys (raw): {decoded_keys}")

            # Attempt to unpack the keys (make sure the format is correct)
            try:
                p, g, x = map(int, decoded_keys.split(',')[:3])  # Only take the first 3 values
                print(f"Received ElGamal keys - p: {p}, g: {g}, x: {x}")
            except ValueError as e:
                print(f"Error unpacking ElGamal keys: {e}")
                print(f"Received ElGamal keys (raw): {decoded_keys}")
                continue  # Skip processing this packet

            # Now receive the signature (r, s)
            signature = client_socket.recv(1024)  # Adjust buffer size as needed
            decoded_signature = signature.decode()
            try:
                r, s = map(int, decoded_signature.split(','))
                print(f"Received signature (r, s): ({r}, {s})")
            except ValueError as e:
                print(f"Error unpacking signature: {e}")
                print(f"Received signature (raw): {decoded_signature}")
                continue  # Skip processing this packet

            # Verify the signature
            print("Signature Validity:", verify_signature(decrypted_message, r, s, p, g, x))

        finally:
            client_socket.close()

if __name__ == "__main__":
    start_server()