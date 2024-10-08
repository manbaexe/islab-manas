from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import rsa
from Crypto.Cipher import DES


# AES-256 key and IV generation
key = get_random_bytes(32)  # 256-bit key
iv = get_random_bytes(16)   # AES block size is 16 bytes
key_des = get_random_bytes(8)  # DES key (8 characters = 64 bits)

public_key, private_key = rsa.newkeys(2048)

# Encrypt function for AES
def encrypt_aes_256(data, key, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(data.encode(), AES.block_size))
    return ciphertext

# Decrypt function for AES
def decrypt_aes_256(ciphertext, key, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
    return plaintext.decode()

# Encrypt function for DES
def des_encrypt(plaintext, key):
    des = DES.new(key, DES.MODE_ECB)  # Use bytes directly
    padded_text = pad(plaintext.encode('utf-8'), DES.block_size)  # Pad the plaintext to match the DES block size (8 bytes)
    ciphertext = des.encrypt(padded_text)  # Encrypt the padded plaintext
    return ciphertext

# Decrypt function for DES
def des_decrypt(ciphertext, key):
    des = DES.new(key, DES.MODE_ECB)  # Use bytes directly
    decrypted_padded_text = des.decrypt(ciphertext)  # Decrypt the ciphertext
    plaintext = unpad(decrypted_padded_text, DES.block_size)  # Unpad the decrypted plaintext
    return plaintext.decode('utf-8')

flag = True

while flag:
    print("Select the sender:")
    print("1. Alice")
    print("2. Bob")
    print("3. Charlie")
    print("4. Quit")
    sender_code = int(input("Enter the sender code: "))
    
    if sender_code == 1:
        sender = "Alice"
    elif sender_code == 2:
        sender = "Bob"
    elif sender_code == 3:
        sender = "Charlie"
    elif sender_code == 4:
        flag = False
        break

    print("Select the receiver:")
    print("1. Alice")
    print("2. Bob")
    print("3. Charlie")
    print("4. Quit")
    receiver_code = int(input("Enter the receiver code: "))
    
    if receiver_code == 1:
        receiver = "Alice"
    elif receiver_code == 2:
        receiver = "Bob"
    elif receiver_code == 3:
        receiver = "Charlie"
    elif receiver_code == 4:
        flag = False
        break

    # Make sure sender and receiver are different
    if sender == receiver:
        print(f"{sender} cannot send a message to themselves.")
        continue

    message = input("Enter the message: ")
    print(f"Sender : {sender}")
    print(f"Receiver : {receiver}")
    print(f"Message sent by {sender} : {message}")

    if (sender == "Alice" and receiver == "Bob") or (sender == "Bob" and receiver == "Alice"):
        ciphertext = encrypt_aes_256(message, key, iv)
        print(f"Ciphertext sent: {ciphertext}")
        print(f"Decrypted message: {decrypt_aes_256(ciphertext, key, iv)}")

    elif (sender == "Alice" and receiver == "Charlie") or (sender == "Charlie" and receiver == "Alice"):
        ciphertext = rsa.encrypt(message.encode('utf-8'), public_key)  # Convert to bytes
        print(f"Ciphertext sent: {ciphertext}")
        decrypted_message = rsa.decrypt(ciphertext, private_key).decode('utf-8')  # Decode the result
        print(f"Decrypted message: {decrypted_message}")

    elif (sender == "Bob" and receiver == "Charlie") or (sender == "Charlie" and receiver == "Bob"):
        ciphertext = des_encrypt(message, key_des)
        print(f"Ciphertext sent: {ciphertext}")
        print("\n")
        print(f"Decrypted message: {des_decrypt(ciphertext, key_des)}")

    print("\n")
