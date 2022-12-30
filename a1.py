

from re import I
from math import log2


ALPHABET = "\n !\"'(),-.0123456789:;?ABCDEFGHIJKLMNOPQRSTUVWXYZ"

def encrypt(text, key):
    """
    encrypt(text, key) - takes a ciphertext (encrypted text) and a short key,
    and deciphers it using vigenere's cipher
    text - Some text as a str. All characters must be in ALPHABET
    key - Some text as a str. All characters must be in ALPHABET
    """
    encrypted = ""
    
    for position in range(len(text)):
        text_character = ALPHABET.index(text[position])
        key_character = ALPHABET.index(key[position % len(key)])
        encrypted_char = (text_character + key_character) % len(ALPHABET)
        encrypted += ALPHABET[encrypted_char]
    return encrypted

def decrypt(text, key):
    """
    decrypt(text, key) - takes a ciphertext (encrypted text) and a short key,
    and deciphers it using vigenere's cipher
    text - Some text as a str. All characters must be in ALPHABET
    key - Some text as a str. All characters must be in ALPHABET
    """
    decrypted = ""
    for position in range(len(text)):
        text_character = ALPHABET.index(text[position])
        key_character = ALPHABET.index(key[position % len(key)])
        decrypted_char = (text_character - key_character + len(ALPHABET)) % len(ALPHABET)
        decrypted += ALPHABET[decrypted_char]
    return decrypted

def get_frequencies(text):
    """
    get_frequencies(text) - takes a ciphertext and calculates the frequency of 
    each character (values between 1.0 and 0.0) and compiles it in a dictionary
    text - Some text as a str. All characters must be in ALPHABET
    """
    letter_frequency = {}
    
    # count the frequencies of letters
    for char in text:
        if char in ALPHABET:
            if char not in letter_frequency:
                letter_frequency[char] = 0
                letter_frequency[char] += 1
            else:
                letter_frequency[char] += 1

    # calculate frequencies so that it is between 1.0 and 0.0
    for key in letter_frequency:
        letter_frequency[key] /= len(text)
    
    return letter_frequency

def cross_entropy(freqs1, freqs2):
    """
    cross_entropy(freqs1, freqs2) - takes two frequencies produced by get_frequencies
    then measures (in bits) the comparison between the two dictionaries of frequencies
    freqs1, freqs2 - dictionaries of letter frequencies
    """

    # list of all the letters that show up in EITHER dictionary
    letters = []
    
    for key in freqs1:
        letters.append(key)
    for key in freqs2:
        if key not in letters:
            letters.append(key)

    # initialize variable total
    total = 0.0
    
    min1 = 0.0
    min2 = 0.0
    
    # minimum frequency greater than zero for freqs1
    for key in freqs1:
        if key in freqs1:
            if min1 == 0 or min1 > freqs1[key]:
                min1 = freqs1[key]

    # minimum frequency greater than zero for freqs2            
    for key in freqs2:
        if key in freqs2:
            if min2 == 0 or min2 > freqs2[key]:
                min2 = freqs2[key]

    # calculate total
    for char in letters:
        if char in freqs1 and char not in freqs2:
            freqs2[char] = min2
        elif char in freqs2 and char not in freqs1:
            freqs1[char] = min1
        total -= freqs1[char] * log2(freqs2[char])
    
    return total

def get_subchars(text, n):
    """
    get_subchars(text, n) - helper function for guess_key
    takes ciphertext and makes a substring based on nth letter
    to be able to attack each letter of the key separately
    text - Some text as a str. All characters must be in ALPHABET 
    n - starting point of the substring
    """
    i = n - 1
    letters = []

    while i < len(text):
        letters.append(text[i])
        i += 3
    return ''.join(letters)

def guess_key(encrypted):
    """
    guess_key(encrypted) - guess the key of the encrypted text in encrypted based on 
    the frequencies in the dictionary english_frequencies, which is computed by reading frank.txt
    encrypted - Some text as a str. All characters must be in ALPHABET
    """
    # length of the key is always 3, therefore 3 substrings
    # separate out the characters encrypted by different letters of the key
    sub1 = get_subchars(encrypted, 1)
    sub2 = get_subchars(encrypted, 2)
    sub3 = get_subchars(encrypted, 3)
    
    with open ("frank.txt", "r") as myfile:
        frank = myfile.read() 
    
    english_frequencies = get_frequencies(frank)
    
    min_entropy1 = 0.0
    min_entropy2 = 0.0
    min_entropy3 = 0.0

    # attack each substring to get the key
    for char in ALPHABET:
        cross1 = cross_entropy(english_frequencies, get_frequencies(decrypt(sub1, char)))
        cross2 = cross_entropy(english_frequencies, get_frequencies(decrypt(sub2, char)))
        cross3 = cross_entropy(english_frequencies, get_frequencies(decrypt(sub3, char)))

        # SMALLEST cross-entropy = key
        if min_entropy1 == 0 or min_entropy1 > cross1:
            min_entropy1 = cross1
            key1 = char
        if min_entropy2 == 0 or min_entropy2 > cross2:
            min_entropy2 = cross2
            key2 = char
        if min_entropy3 == 0 or min_entropy3 > cross3:
            min_entropy3 = cross3
            key3 = char
    # combine each character's key to get full 3 character key
    key = key1 + key2 + key3
    
    return key

def crack(encrypted_text):
    """
    crack(encrypted_text) - decrypts the text string encrypted_text and 
    returns the decrypted text, without knowing the key
    encrypted_text - Some text as a str. All characters must be in ALPHABET
    """

    key = guess_key(encrypted_text)
    decrypted = decrypt(encrypted_text, key)

    return decrypted

def main():

    text = "I LOVE PIZZA!"
    key = "YUM"
    encrypted_text = "GV:MP3ZJ7XT."

    with open ("frank_encrypted.txt", "r") as myfile:
        frank_encrypted = myfile.read()

    with open ("frank.txt", "r") as myfile:
        frank = myfile.read()

    with open ("secret1_encrypted.txt", "r") as myfile:
        secret1_encrypted = myfile.read()
    
    with open ("secret2_encrypted.txt", "r") as myfile:
        secret2_encrypted = myfile.read()
    
    with open ("secret3_encrypted.txt", "r") as myfile:
        secret3_encrypted = myfile.read()
    """
    print(encrypt(text,key))

    print(decrypt(encrypted_text,key))

    print(get_frequencies(text))

    freqs1 = get_frequencies(frank[:2000])
    freqs2 = get_frequencies(frank_encrypted[:2000])

    print(cross_entropy(freqs1, freqs2))
    print(guess_key(frank_encrypted[:2000]))
    """

    #print(crack(frank_encrypted[:2000]))
    #print(crack(secret1_encrypted))
    #print(crack(secret2_encrypted))
    print(crack(secret3_encrypted))

if __name__=="__main__":
    main()