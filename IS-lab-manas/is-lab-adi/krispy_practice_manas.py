import rsa
import hashlib
import time
from Crypto.PublicKey import DSA
from Crypto.Hash import SHA256
from Crypto.Random import random


# Step 1: Generate DSA keys (Schnorr is typically implemented with DSA-style keys)
def generate_keys():
    private_key = DSA.generate(2048)
    public_key = private_key.publickey()
    return private_key, public_key


# Step 2: Sign the message using the private key
def sign_message(private_key, message):
    # Hash the message using SHA-256
    hash_obj = SHA256.new(message.encode('utf-8'))

    # Generate a random value k for signing
    k = random.StrongRandom().randint(1, private_key.q - 1)

    # Generate signature (r, s)
    r = pow(private_key.g, k, private_key.p) % private_key.q
    k_inv = pow(k, private_key.q - 2, private_key.q)  # modular inverse of k mod q
    s = (k_inv * (int(hash_obj.hexdigest(), 16) + private_key.x * r)) % private_key.q

    return (r, s)


# Step 3: Verify the signature using the public key
def verify_signature(public_key, message, signature):
    r, s = signature
    if not (0 < r < public_key.q) or not (0 < s < public_key.q):
        return False

    # Hash the message using SHA-256
    hash_obj = SHA256.new(message.encode('utf-8'))

    # Calculate w = s^(-1) mod q
    w = pow(s, public_key.q - 2, public_key.q)

    # Calculate u1 = hash(message) * w mod q
    u1 = (int(hash_obj.hexdigest(), 16) * w) % public_key.q

    # Calculate u2 = r * w mod q
    u2 = (r * w) % public_key.q

    # Calculate v = ((g^u1 * y^u2) mod p) mod q
    v = ((pow(public_key.g, u1, public_key.p) * pow(public_key.y, u2, public_key.p)) % public_key.p) % public_key.q

    # Signature is valid if v == r
    return v == r


def sha512_hash(message):
    # Create a new sha512 hash object
    sha512 = hashlib.sha512()

    # Update the hash object with the bytes of the message
    sha512.update(message.encode('utf-8'))

    # Return the hexadecimal digest of the hash
    return sha512.hexdigest()


validator_rsa_public_key, validator_rsa_private_key = rsa.newkeys(2048)
ga_rsa_public_key, ga_rsa_private_key = rsa.newkeys(2048)
timestamps=[]
msgdic = []
msgdic2 = []
timestamps2 = []

flag = True
while flag:
    print("select the user")
    print("1. Government authority sending")
    print("2. validator recieving")
    print("3. validator sending")
    print("4. Government authority recieving")
    print("5. auditor")
    print("6. quit")
    code = int(input("enter user mode:"))

    if code == 1:

        message = input("Enter the message to send")
        encoded_message = message.encode('utf-8')
        ciphertext = rsa.encrypt(encoded_message, validator_rsa_public_key)
        hashed_message = sha512_hash(message)
        msgdic.append(hashed_message)
        timestamps.append(time.time())
        ga_schnorr_private_key, ga_schnorr_public_key = generate_keys()
        signature = sign_message(ga_schnorr_private_key, hashed_message)
        print("Encrypted Message:", ciphertext)




    elif code == 2:
        decrypted_message = rsa.decrypt(ciphertext, validator_rsa_private_key)
        print(decrypted_message)
        is_valid = verify_signature(ga_schnorr_public_key, hashed_message, signature)
        print("Signature is valid:", is_valid)
        if is_valid:
            print("Signature is valid.")
        else:
            print("Signature is invalid.")




    elif code == 3:
        message2 = input("Enter the message to send")
        encoded_message2 = message2.encode('utf-8')
        ciphertext2 = rsa.encrypt(encoded_message2, ga_rsa_public_key)
        hashed_message2 = sha512_hash(message2)
        msgdic2.append(hashed_message2)
        timestamps2.append(time.time())
        validator_schnorr_private_key, validator_schnorr_public_key = generate_keys()
        signature2 = sign_message(validator_schnorr_private_key, hashed_message2)
        print("Encrypted Message:", ciphertext2)


    elif code == 4:

        decrypted_message2 = rsa.decrypt(ciphertext2, ga_rsa_private_key)
        print(decrypted_message2)
        is_valid2 = verify_signature(validator_schnorr_public_key, hashed_message2, signature2)
        print("Signature is valid:", is_valid2)
        if is_valid2:
            print("Signature is valid., payment confirmed from both sides")
        else:
            print("Signature is invalid.")

    elif code ==  5:
        print(timestamps)
        print(msgdic)
        print(timestamps2)
        print(msgdic2)

    elif code == 6:
        flag = False
        break