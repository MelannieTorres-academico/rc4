# References
# https://stackoverflow.com/questions/14678132/python-hexadecimal
# https://stackoverflow.com/questions/36242887/how-to-xor-two-strings-in-python/36242949
# https://stackoverflow.com/questions/231767/what-does-the-yield-keyword-do
# https://github.com/bozhu/RC4-Python/blob/master/rc4.py
import fileinput

#recives a string key 
#returns a list S
def ksa(key):
    S = []
    for i  in range(256):
        S.append(i)
    j=0
    for i  in range(256):
        j = (j + S[i] + ord(key[i % len(key)])) % 256
        S[i], S[j] = S[j], S[i]
    return S

#recieves a list S
#returns a generator object
def prga(S):
    i=0
    j=0
    while True:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        K = S[(S[i] + S[j]) % 256]
        yield K

# xors a char with an int
# recieves a char char_a and an int int_b
# returns a 0 or a 1
def xor(char_a, int_b):
    return ord(char_a) ^ int_b

#ciphers a message into a ciphertext
#recieves a string message and a generator stream
#returns a string ciphertext
def rc4(message, stream):
    ciphertext = ''
    for word in message:
        for letter in word:
            ciphertext += int_to_hex(xor(letter, stream.__next__()))
            if(letter == "\n"):
                return ciphertext
    return ciphertext

#transforms an int into a formatted hex
#recieves an int int_a
#returns an hexadecimal
def int_to_hex(int_a):
    return format(int_a, '02X')

#decripts a ciphered text (only used to proof question 2)
# recieves a ciphertext and the generator object
# returns a string of the plaintext
def decrypt(ciphertext, stream):
    plaintext = ''
    pairs = [ciphertext[i:i+2] for i in range(0, len(ciphertext), 2)]
    for hex_value in pairs:
        int_value = int(hex_value, 16)
        xored = int_value ^ stream.__next__()
        plaintext += chr(xored)
    return plaintext


def main():
    file_input = fileinput.input()
    key = file_input[0].replace("\n", "")
    S = ksa(key)
    stream = prga(S)
    ciphertext = rc4(file_input, stream)
    print(ciphertext)
    # plaintext = decrypt('BBF316E8D940AF0AD313', stream)
    # print(plaintext)


if __name__ == "__main__":
    main()
