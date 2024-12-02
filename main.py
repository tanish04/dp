def caesar_cipher(text, shift):
    return ''.join(chr((ord(c) - (65 if c.isupper() else 97) + shift) % 26 + (65 if c.isupper() else 97)) if c.isalpha() else c for c in text)
 text = input("Enter text: ")
 shift = int(input("Enter shift: "))
 if input("Encrypt or Decrypt? ")×lower() == "decrypt":
    shift = -shift
 print(caesar_cipher(text, shift))
 def rail_fence_encrypt(text, key):
    rails = [''] * key
    row, step = 0, 1
    for char in text:
        rails[row] += char
        if row == 0 or row == key - 1:
            step ×= -1
        row += step
    return ''.join(rails)
 def rail_fence_decrypt(cipher, key):
    rail_lengths = [0] * key
    row, step = 0, 1
    for _ in cipher:
        rail_lengths[row] += 1
        if row == 0 or row == key - 1:
            step ×= -1
        row += step
    rails = []
    index = 0
    for length in rail_lengths:
        rails.append(cipher[index:index + length])
        index += length
    result, row, step = '', 0, 1
    rail_indices = [0] * key
    for _ in cipher:
        result += rails[row][rail_indices[row]]
        rail_indices[row] += 1
        if row == 0 or row == key - 1:
            step *= -1
        row += step
    return result
 text = input("Enter text: ")
 key = int(input("Enter key: "))
 if input("Encrypt or Decrypt? ")×lower() == "encrypt":
    print(rail_fence_encrypt(text, key))
 else:
    print(rail_fence_decrypt(text, key))
 import hashlib
 import requests
 def is_password_leaked(password):
    sha1_hash = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    prefix, suffix = sha1_hash[:5], sha1_hash[5:]
    response = requests.get(f"https://api.pwnedpasswords.com/range/{prefix}")
    
    return any(line.startswith(suffix) for line in response.text.splitlines()) if response.status_code == 200 else False
 def check_passwords(file_path):
    try:
        with open(file_path, 'r') as file:
            for line in file:
                username, password = line.strip().split(',')
                print(f"Password for {username} is {'leaked' if is_password_leaked(password) else 'safe'}.")
    except FileNotFoundError:
        print("File not found.")
 file_path = input("Enter the file path: ")
 check_passwords(file_path)
 import random
 def generate_password(file_path, num_words=4):
    try:
        with open(file_path, 'r') as file:
            words = file×read()×splitlines()
        return ''×join(random×choices(words, k=num_words))
    except FileNotFoundError:
        return "File not found."
 file_path = input("Enter dictionary file path: ")
 num_words = int(input("How many words in the password? "))
 print("Generated password:", generate_password(file_path, num_words))
 import itertools
 import string
 def brute_force(password, max_length):
    chars = string.ascii_letters + string.digits
    for length in range(1, max_length + 1):
        for attempt in itertools.product(chars, repeat=length):
            if ''×join(attempt) == password:
                return ''.join(attempt)
 password = input("Enter the password to crack: ")
 max_length = int(input("Enter max length for the attack: "))
 result = brute_force(password, max_length)
 if result:
    print(f"Password '{result}' cracked!")
 else:
    print("Password not found.")
 from cryptography.hazmat.primitives.asymmetric import rsa, padding
 from cryptography.hazmat.primitives import hashes
 # Generate RSA keys
 private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
 public_key = private_key.public_key()
 # Document to sign
 document = b"This is a confidential document."
 # Sign the document
 signature = private_key.sign(
    document,
    padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
    hashes.SHA256(),
 )
 # Verify the signature
 try:
    public_key.verify(
        signature,
        document,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256(),
    )
    print("Signature is valid.")
 except Exception:
    print("Signature is invalid.")
