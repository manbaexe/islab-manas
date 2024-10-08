import numpy as np

def hill_cipher_encrypt(message, key_matrix):
    # Remove spaces from the message and convert to lowercase
    message = message.replace(" ", "").lower()
    
    # If the message length is odd, pad it with 'x' to make it even
    if len(message) % 2 != 0:
        message += 'x'
    
    # Convert each character to its corresponding number (0 for 'a', 1 for 'b', etc.)
    message_numbers = [ord(char) - ord('a') for char in message]
    
    encrypted_message = ""  # Initialize the encrypted message
    
    # Process the message in pairs of two characters
    for i in range(0, len(message_numbers), 2):
        # Create a column vector from the pair of numbers (corresponding to the letters)
        pair_vector = np.array([[message_numbers[i]], [message_numbers[i+1]]])
        
        # Multiply the key matrix by the pair vector, and apply modulo 26
        encrypted_vector = np.dot(key_matrix, pair_vector) % 26
        
        # Convert the resulting numbers back to characters
        encrypted_message += chr(encrypted_vector[0, 0] + ord('a'))  # First character
        encrypted_message += chr(encrypted_vector[1, 0] + ord('a'))  # Second character
    
    return encrypted_message

# Key matrix for the Hill cipher (2x2 matrix)
key_matrix = np.array([[3, 3], [2, 7]])

# Message to be encrypted
message = "We live in an insecure world"

# Encrypt the message using the Hill cipher
encrypted_message = hill_cipher_encrypt(message, key_matrix)
print("\nEncrypted Message:", encrypted_message)