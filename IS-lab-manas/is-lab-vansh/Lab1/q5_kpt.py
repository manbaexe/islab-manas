def find_shift(plaintext, ciphertext):
    """
    Function to determine the shift key used in a Caesar cipher given the plaintext and ciphertext.
    Assumes the same shift is applied to all characters.
    """
    # Convert the first letter of both plaintext and ciphertext to their alphabetic indices
    # ord('a') = 97, so subtracting 97 converts 'a' to 0, 'b' to 1, ..., 'z' to 25
    shift = (ord(ciphertext[0].lower()) - ord(plaintext[0].lower())) % 26
    return shift

def decrypt_caesar_cipher(ciphertext, shift):
    """
    Decrypts a Caesar cipher given a ciphertext and the shift key.
    """
    decrypted_text = ""
    
    for char in ciphertext:
        if char.isalpha():  # Check if the character is a letter
            offset = ord('a') if char.islower() else ord('A')
            decrypted_text += chr((ord(char) - offset - shift) % 26 + offset)
        else:
            decrypted_text += char  # Non-alphabetic characters are added unchanged
    
    return decrypted_text


# Known plaintext and corresponding ciphertext
plaintext = "yes"
ciphertext = "CIW"

# Find the shift key used
shift = find_shift(plaintext, ciphertext)
print(f"Determined Shift: {shift}")

# Ciphertext to decrypt
ciphertext_to_decrypt = "XVIEWYWI"

# Decrypt the ciphertext using the found shift key
decrypted_message = decrypt_caesar_cipher(ciphertext_to_decrypt, shift)
print(f"Decrypted Message: {decrypted_message}")