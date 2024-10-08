from sympy import mod_inverse

def affine_decrypt(ciphertext, a, b):
    """
    Function to decrypt a ciphertext using the Affine cipher.
    :param ciphertext: The ciphertext to be decrypted.
    :param a: Multiplicative key 'a' in the Affine cipher formula.
    :param b: Additive key 'b' in the Affine cipher formula.
    :return: The decrypted plaintext.
    """
    # Find the modular inverse of 'a' under modulo 26
    a_inv = mod_inverse(a, 26)
    
    # If there is no inverse, raise an error (a must be coprime with 26)
    if a_inv is None:
        raise ValueError(f"No modular inverse for a={a} under modulo 26.")
    
    plaintext = ""
    
    # Loop through each character in the ciphertext
    for char in ciphertext:
        if char.isalpha():  # Only decrypt alphabetic characters
            # Convert the character to an index (A=0, B=1, ..., Z=25)
            y = ord(char) - ord('A')
            # Apply the Affine decryption formula: x = a_inv * (y - b) % 26
            x = (a_inv * (y - b)) % 26
            # Convert back to a character and append to the plaintext
            plaintext += chr(x + ord('a'))
        else:
            # Non-alphabetic characters are added unchanged
            plaintext += char
    
    return plaintext

# Given ciphertext and known character pairs
ciphertext = "XPALASXYFGFUKPXUSOGEUTKCDGEXANMGNVS"

# Known plain text and cipher text pairs
plain_pair = (0, 1)   # (plain text letters)
cipher_pair = (6, 11)  # Corresponding cipher text letters (A = 6, B = 11)

# Extract 'b' directly from the cipher pair
b = cipher_pair[0]

# Calculate 'a' based on the difference between the pairs
a = (cipher_pair[1] - b) % 26

# Decrypt the ciphertext using the determined keys
decrypted_message = affine_decrypt(ciphertext, a, b)

print("\nDecrypted Message:", decrypted_message)