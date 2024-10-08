def decrypt(ciphertext, key):
    """
    Decrypts a given ciphertext using a Caesar cipher (shift cipher) with the provided key.
    
    :param ciphertext: The encrypted message to be decrypted.
    :param key: The shift key used for decryption.
    :return: The decrypted plaintext.
    """
    plaintext = ''
    
    # Loop through each character in the ciphertext
    for char in ciphertext:
        if char.isalpha():  # Only decrypt alphabetic characters
            # Determine the base (A=65 for uppercase, a=97 for lowercase)
            shift = ord('A') if char.isupper() else ord('a')
            # Decrypt using the formula: (current character - shift - key) % 26 + shift
            decrypted_char = chr((ord(char) - shift - key) % 26 + shift)
            plaintext += decrypted_char
        else:
            # Non-alphabetic characters are added unchanged
            plaintext += char
    
    return plaintext

# Ciphertext message to be decrypted
ciphertext = "NCJAEZRCLAS/LYODEPRLYZRCLASJLCPEHZDTOPDZOLN&BY"

# Brute force decryption by trying possible keys (e.g., around Alice's birthday 13)
for key in range(1, 26):
    print(f"Trying key {key}: {decrypt(ciphertext, key)}")