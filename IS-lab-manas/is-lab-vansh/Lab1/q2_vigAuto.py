def vigenere_cipher(plaintext, key):
    encrypted = ""
    decrypted = ""
    key = key.lower()  # Convert the key to lowercase to handle case insensitivity
    key_length = len(key)  # Get the length of the key
    key_index = 0  # Index to track the position in the key
    
    # Encrypting
    for char in plaintext:
        if char.isalpha():  # Encrypt only alphabetic characters
            offset = ord('a')  # Use 'a' as the base ASCII value (for lowercase letters)
            p = ord(char) - offset  # Convert the current plaintext letter to 0-25 range
            k = ord(key[key_index % key_length]) - offset  # Get the corresponding key letter value in 0-25 range
            encrypted += chr((p + k) % 26 + offset)  # Apply Vigenère cipher formula: (p + k) % 26
            key_index += 1  # Move to the next key character
        else:
            encrypted += char  # Non-alphabet characters remain unchanged
    
    key_index = 0  # Reset key index for decryption
    # Decrypting
    for char in encrypted:
        if char.isalpha():  # Decrypt only alphabetic characters
            offset = ord('a')  # Use 'a' as the base ASCII value (for lowercase letters)
            c = ord(char) - offset  # Convert the ciphertext letter to 0-25 range
            k = ord(key[key_index % key_length]) - offset  # Get the corresponding key letter value in 0-25 range
            decrypted += chr((c - k + 26) % 26 + offset)  # Apply reverse of Vigenère cipher formula: (c - k) % 26
            key_index += 1  # Move to the next key character
        else:
            decrypted += char  # Non-alphabet characters remain unchanged
    
    return encrypted, decrypted


def autokey_cipher(plaintext, initial_key):
    encrypted = ""
    decrypted = ""
    
    # The key starts with the initial key, followed by the numeric values of the plaintext characters
    key = [initial_key] + [ord(char) - ord('a') for char in plaintext]
    key_index = 0  # Index to track the key position
    
    # Encrypting
    for i, char in enumerate(plaintext):
        if char.isalpha():  # Encrypt only alphabetic characters
            offset = ord('a')  # Use 'a' as the base ASCII value
            p = ord(char) - offset  # Convert the plaintext letter to 0-25 range
            k = key[key_index]  # Get the key value from the key list
            encrypted += chr((p + k) % 26 + offset)  # Apply Autokey cipher formula: (p + k) % 26
            key_index += 1  # Move to the next key value
        else:
            encrypted += char  # Non-alphabet characters remain unchanged
    
    key_index = 0  # Reset key index for decryption
    # Decrypting
    for i, char in enumerate(encrypted):
        if char.isalpha():  # Decrypt only alphabetic characters
            offset = ord('a')  # Use 'a' as the base ASCII value
            c = ord(char) - offset  # Convert the ciphertext letter to 0-25 range
            k = key[key_index]  # Get the key value from the key list
            decrypted_char = chr((c - k + 26) % 26 + offset)  # Apply reverse of Autokey cipher formula: (c - k) % 26
            decrypted += decrypted_char  # Add the decrypted character to the result
            key[key_index + 1] = ord(decrypted_char) - offset  # Update the key with the decrypted character
            key_index += 1  # Move to the next key value
        else:
            decrypted += char  # Non-alphabet characters remain unchanged
    
    return encrypted, decrypted


# Test the Vigenère cipher with the message
message = "the house is being sold tonight"

# Vigenère cipher with key = "dollars"
vigenere_encrypted, vigenere_decrypted = vigenere_cipher(message, "dollars")
print(f"Vigenere Cipher:\nEncrypted: {vigenere_encrypted}\nDecrypted: {vigenere_decrypted}\n")

# Test the Autokey cipher with the message
message = "thehouseisbeingsoldtonight"  # Spaces are removed for simplicity

# Autokey cipher with initial key = 7
autokey_encrypted, autokey_decrypted = autokey_cipher(message, 7)
print(f"Autokey Cipher:\nEncrypted: {autokey_encrypted}\nDecrypted: {autokey_decrypted}")