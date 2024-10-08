def additive_cipher(plaintext, key):
    encrypted = ""
    decrypted = ""
    
    # Encrypting
    for char in plaintext:
        if char.isalpha():  # Check if the character is a letter
            # Determine whether to work in the upper or lower case range
            offset = ord('A') if char.isupper() else ord('a')
            # Apply the additive cipher formula: (current letter - 'A' + key) % 26
            encrypted += chr((ord(char) - offset + key) % 26 + offset)
        else:
            encrypted += char  # Non-alphabet characters are unchanged
    
    # Decrypting
    for char in encrypted:
        if char.isalpha():  # Check if the character is a letter
            offset = ord('A') if char.isupper() else ord('a')
            # Apply the reverse of the additive cipher formula: (current letter - 'A' - key) % 26
            decrypted += chr((ord(char) - offset - key + 26) % 26 + offset)
        else:
            decrypted += char  # Non-alphabet characters are unchanged
    
    return encrypted, decrypted


def multiplicative_cipher(plaintext, key):
    # Multiplicative inverse of 15 mod 26 is precomputed as 7
    inverse_key = 7
    encrypted = ""
    decrypted = ""
    
    # Encrypting
    for char in plaintext:
        if char.isalpha():  # Check if the character is a letter
            offset = ord('A') if char.isupper() else ord('a')
            # Apply the multiplicative cipher formula: (current letter - 'A') * key % 26
            encrypted += chr(((ord(char) - offset) * key) % 26 + offset)
        else:
            encrypted += char  # Non-alphabet characters are unchanged
    
    # Decrypting
    for char in encrypted:
        if char.isalpha():  # Check if the character is a letter
            offset = ord('A') if char.isupper() else ord('a')
            # Apply the reverse of the multiplicative cipher: (current letter - 'A') * inverse_key % 26
            decrypted += chr(((ord(char) - offset) * inverse_key) % 26 + offset)
        else:
            decrypted += char  # Non-alphabet characters are unchanged
    
    return encrypted, decrypted


def affine_cipher(plaintext, key1, key2):
    # Multiplicative inverse of 15 mod 26 is precomputed as 7
    inverse_key1 = 7
    encrypted = ""
    decrypted = ""
    
    # Encrypting
    for char in plaintext:
        if char.isalpha():  # Check if the character is a letter
            offset = ord('A') if char.isupper() else ord('a')
            # Apply the affine cipher formula: ((current letter - 'A') * key1 + key2) % 26
            encrypted += chr(((ord(char) - offset) * key1 + key2) % 26 + offset)
        else:
            encrypted += char  # Non-alphabet characters are unchanged
    
    # Decrypting
    for char in encrypted:
        if char.isalpha():  # Check if the character is a letter
            offset = ord('A') if char.isupper() else ord('a')
            # Apply the reverse of the affine cipher: ((current letter - 'A' - key2) * inverse_key1) % 26
            decrypted += chr(((ord(char) - offset - key2 + 26) * inverse_key1) % 26 + offset)
        else:
            decrypted += char  # Non-alphabet characters are unchanged
    
    return encrypted, decrypted


# Test the ciphers with the message
message = "I am learning information security"

# Additive cipher with key = 20
additive_encrypted, additive_decrypted = additive_cipher(message, 20)
print(f"Additive Cipher:\nEncrypted: {additive_encrypted}\nDecrypted: {additive_decrypted}\n")

# Multiplicative cipher with key = 15
multiplicative_encrypted, multiplicative_decrypted = multiplicative_cipher(message, 15)
print(f"Multiplicative Cipher:\nEncrypted: {multiplicative_encrypted}\nDecrypted: {multiplicative_decrypted}\n")

# Affine cipher with key = (15, 20)
affine_encrypted, affine_decrypted = affine_cipher(message, 15, 20)
print(f"Affine Cipher:\nEncrypted: {affine_encrypted}\nDecrypted: {affine_decrypted}")