def vigenere_cipher_encrypt(plaintext, keyword):
    """
    Encrypts a given plaintext using the Vigenère cipher with the provided keyword.
    
    :param plaintext: The message to be encrypted.
    :param keyword: The keyword used for encryption.
    :return: The encrypted ciphertext.
    """
    keyword_repeated = []  # To store the repeated keyword to match the length of the plaintext
    keyword_length = len(keyword)
    key_index = 0  # Tracks the current position in the keyword
    
    # Repeat the keyword to match the length of the plaintext (skipping non-alphabet characters)
    for char in plaintext:
        if char.isalpha():  # Only repeat the keyword for alphabetic characters
            keyword_repeated.append(keyword[key_index % keyword_length].upper())  # Repeat and convert to uppercase
            key_index += 1
        else:
            keyword_repeated.append(char)  # Keep spaces and punctuation unchanged
    
    ciphertext = []  # To store the final encrypted message
    
    # Encrypt the plaintext
    for i, char in enumerate(plaintext):
        if char.isalpha():  # Only encrypt alphabetic characters
            shift = ord(keyword_repeated[i]) - ord('A')  # Calculate the shift based on the keyword letter
            shift_base = ord('A') if char.isupper() else ord('a')  # Handle case sensitivity (uppercase/lowercase)
            encrypted_char = chr((ord(char) - shift_base + shift) % 26 + shift_base)  # Encrypt the character
            ciphertext.append(encrypted_char)  # Add the encrypted character to the result
        else:
            ciphertext.append(char)  # Keep non-alphabetic characters unchanged
    
    return ''.join(ciphertext)  # Combine the list of characters into a single string

# Example usage
plaintext = "Life is full of surprises"
keyword = "HEALTH"

ciphertext = vigenere_cipher_encrypt(plaintext, keyword)
print(f"Ciphertext: {ciphertext}")