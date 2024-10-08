def create_playfair_matrix(keyword):
    matrix = []
    used_chars = set()  # Set to keep track of characters already added to the matrix
    keyword = keyword.replace('j', 'i').lower()  # Replace 'j' with 'i' and make the keyword lowercase
    
    # Add characters from the keyword to the matrix, ensuring no duplicates
    for char in keyword:
        if char not in used_chars and char.isalpha():  # Add only alphabetic characters
            matrix.append(char)
            used_chars.add(char)  # Mark character as used
    
    # Add remaining characters of the alphabet (excluding 'j') to the matrix
    for char in 'abcdefghiklmnopqrstuvwxyz':  # 'j' is excluded
        if char not in used_chars:
            matrix.append(char)
            used_chars.add(char)  # Mark character as used
    
    # Convert the 25-character list into a 5x5 matrix
    return [matrix[i:i+5] for i in range(0, 25, 5)]


def preprocess_message(message):
    message = message.lower().replace('j', 'i').replace(" ", "")  # Convert message to lowercase, replace 'j' with 'i', and remove spaces
    processed_message = ""
    
    i = 0
    while i < len(message):
        if i == len(message) - 1:  # If there's a single character left, add 'x' to complete the pair
            processed_message += message[i] + 'x'
            i += 1
        elif message[i] == message[i + 1]:  # If two consecutive characters are the same, insert 'x' between them
            processed_message += message[i] + 'x'
            i += 1
        else:
            processed_message += message[i] + message[i + 1]  # Otherwise, process two characters at a time
            i += 2
    return processed_message


def find_position(matrix, char):
    # Loop through the matrix to find the row and column of the given character
    for row in range(5):
        for col in range(5):
            if matrix[row][col] == char:
                return row, col
    return None


def playfair_encrypt(matrix, message):
    encrypted_message = ""
    
    # Process the message in pairs of two characters
    for i in range(0, len(message), 2):
        char1 = message[i]
        char2 = message[i + 1]
        row1, col1 = find_position(matrix, char1)  # Find the position of the first character in the matrix
        row2, col2 = find_position(matrix, char2)  # Find the position of the second character in the matrix
        
        if row1 == row2:  # If the two characters are in the same row, shift columns to the right
            encrypted_message += matrix[row1][(col1 + 1) % 5] + matrix[row2][(col2 + 1) % 5]
        elif col1 == col2:  # If the two characters are in the same column, shift rows down
            encrypted_message += matrix[(row1 + 1) % 5][col1] + matrix[(row2 + 1) % 5][col2]
        else:  # If the characters are in different rows and columns, form a rectangle and swap columns
            encrypted_message += matrix[row1][col2] + matrix[row2][col1]
    
    return encrypted_message


# Example usage:

secret_key = "GUIDANCE"  # The keyword used to generate the Playfair matrix
message = "The key is hidden under the door pad"  # The message to be encrypted

# Create the Playfair matrix from the keyword
matrix = create_playfair_matrix(secret_key)
print("Playfair Matrix:")
for row in matrix:
    print(row)

# Preprocess the message: convert to lowercase, replace 'j' with 'i', remove spaces, and handle double letters
processed_message = preprocess_message(message)
print("\nProcessed Message:", processed_message)

# Encrypt the message using the Playfair cipher and the generated matrix
encrypted_message = playfair_encrypt(matrix, processed_message)
print("\nEncrypted Message:", encrypted_message)