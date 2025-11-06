## Caesar Cipher Implementation

# Define the character set (string containing all possible characters)
# Includes lowercase, uppercase, digits, and common symbols/punctuation, including space
CHARACTER_SET = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+-=[]{}\\|;:'\",./<>? `~"
SET_SIZE = len(CHARACTER_SET)

def encrypt(plaintext, key):
    ciphertext = ""
    # Ensure the key is within the bounds of the character set size
    # This handles large positive and negative keys
    key = key % SET_SIZE

    for char in plaintext:
        # Check if the character is in the defined set
        if char in CHARACTER_SET:
            # Find the current position (index) of the character
            current_index = CHARACTER_SET.index(char)
            # Calculate the new position after the shift
            # Use the modulo operator (%) to wrap around the set
            new_index = (current_index + key) % SET_SIZE
            # Get the new character from the character set at the new index
            encrypted_char = CHARACTER_SET[new_index]
            ciphertext += encrypted_char
        else:
            # If the character is not in the set, append it as is (optional, 
            # but good for handling extremely rare or non-standard characters)
            ciphertext += char

    return ciphertext

def decrypt(ciphertext, key):
    decryption_key = -key
    # Reuse the encrypt function with the negative key
    plaintext = encrypt(ciphertext, decryption_key)
    return plaintext

def main():
    """
    Handles user interaction and choice between encryption and decryption.
    """
    print("✨ Caesar Cipher Tool ✨")
    print("-" * 30)

    while True:
        mode = input("Do you want to (E)encrypt or (D)decrypt? (E/D): ").upper()
        if mode in ['E', 'D']:
            break
        print("Invalid choice. Please enter 'E' for Encrypt or 'D' for Decrypt.")

    while True:
        try:
            key = int(input("Enter the *shift key* (an integer): "))
            break
        except ValueError:
            print("Invalid input. Please enter a valid integer for the key.")

    if mode == 'E':
        text = input("Enter the text to encrypt: ")
        result = encrypt(text, key)
        print("\nEncrypted Text (Ciphertext):")
        print(f" {result} ")
    
    elif mode == 'D':
        text = input("Enter the text to decrypt: ")
        result = decrypt(text, key)
        print("\nDecrypted Text (Plaintext):")
        print(f" {result} ")

    print("-" * 30)
    print("Operation complete.")


