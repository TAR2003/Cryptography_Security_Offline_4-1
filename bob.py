from BitVector import *
import random
from random import randint
from sympy import randprime
import math
import json
import time

Sbox = (
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
)

InvSbox = (
    0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
    0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
    0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
    0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
    0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
    0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
    0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
    0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
    0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
    0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
    0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
    0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
    0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
    0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
    0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D,
)

Mixer = [
    [BitVector(hexstring="02"), BitVector(hexstring="03"), BitVector(hexstring="01"), BitVector(hexstring="01")],
    [BitVector(hexstring="01"), BitVector(hexstring="02"), BitVector(hexstring="03"), BitVector(hexstring="01")],
    [BitVector(hexstring="01"), BitVector(hexstring="01"), BitVector(hexstring="02"), BitVector(hexstring="03")],
    [BitVector(hexstring="03"), BitVector(hexstring="01"), BitVector(hexstring="01"), BitVector(hexstring="02")]
]

InvMixer = [
    [BitVector(hexstring="0E"), BitVector(hexstring="0B"), BitVector(hexstring="0D"), BitVector(hexstring="09")],
    [BitVector(hexstring="09"), BitVector(hexstring="0E"), BitVector(hexstring="0B"), BitVector(hexstring="0D")],
    [BitVector(hexstring="0D"), BitVector(hexstring="09"), BitVector(hexstring="0E"), BitVector(hexstring="0B")],
    [BitVector(hexstring="0B"), BitVector(hexstring="0D"), BitVector(hexstring="09"), BitVector(hexstring="0E")]
]

rcon10 = [0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40,0x80, 0x1B, 0x36]

def leftRotateWord(word):
    return word[1:] + word[:1]

def invLeftRotateWord(word):
    return word[-1:] + word[:-1]

def sub_word(word):
    return [Sbox[b] for b in word]

def xor_lists(a, b):
    return [x ^ y for x, y in zip(a, b)]

def key_schedule(key):
    newkey = []
    N = 4
    R = 11
    # print('keys:' , key)
    words = [[ord(c) for c in key[i:i+4]] for i in range(0, len(key), 4)]
    # print(words)
    W = []
    for i in range (0, 4 * R):
        if i < N:
            W.append(words[i])
        elif i >= N and i % N == 0:
            tempWord =xor_lists( W[i - N], sub_word(leftRotateWord(W[i - 1])))
            tempWord[0] = tempWord[0]  ^ rcon10 [(i//N)]
            W.append(tempWord)
        elif i >= N and N > 6 and i % N == 4:
            tempWord = xor_lists(W[i - N] , sub_word(W[i - 1]))
            W.append(tempWord)
        else :
            tempWord = xor_lists(W[i - N] , W[i - 1])
            W.append(tempWord) 
        
    
    for i in range(0, len(W)):
        for j in range(0, len(W[i])):
            W[i][j] = hex(W[i][j])
    # print(W)
    return W
 
def padding_Process(user_plaintText_bytes):
    l = len(user_plaintText_bytes)
    padding_len = 16 - (l % 16)
    for i in range (0,padding_len):
        user_plaintText_bytes.append(hex(padding_len))
    return user_plaintText_bytes

def makeHex(user_text):
    return [hex(ord(c)) for c in user_text]
def makeBlock(user_plainText_Hex):
    one_block = []
    # print('user plainttext : ' , user_plainText_Hex)
    for j in range (0, 8, 2):
        one_block.append(user_plainText_Hex[j:j+2])
    return one_block


def subBytes(user_plainText_Hex):
    transformed_block = []
    
    for row in user_plainText_Hex:
        new_row = []  # Only one block in the outer list
        for byte in row:    
            temp = byte
            t = Sbox[temp]
            new_row.append((Sbox[temp]))
        transformed_block.append(new_row)
    return transformed_block

def invSubBytes(state):
    transformed_block = []
    for row in state:
        new_row = []
        for byte in row:
            new_row.append(InvSbox[byte])  # Use inverse S-box
        transformed_block.append(new_row)
    return transformed_block

def mix_columns(state):
    result = []
    AES_modulus = BitVector(bitstring='100011011')
    for i in range (0,4):
        for j in range (0,4):
            state[i][j] = hex(state[i][j])
    for col in range(0,4):
        column = [BitVector(hexstring=state[row][col][2:]) for row in range(4)]
        t = []
        for row in range(4):
            new_val = BitVector(intVal=0, size=8)
            
            for k in range(4):
                product = Mixer[row][k].gf_multiply_modular(column[k], AES_modulus, 8)
                new_val ^= product
            t.append(int(('0x' + new_val.get_bitvector_in_hex()), 16))
        result.append(t)
    # for i in range (0,4):
    #     for j in range (0,4):
    #         result[i][j] = hex(result[i][j])
    return [[result[row][col] for row in range(4)] for col in range(4)]

def invMixColumns(state):
    result = []
    AES_modulus = BitVector(bitstring='100011011')  # AES modulus (0x11B)
    
    # Convert state to BitVector objects
    for col in range(4):
        column = [BitVector(intVal=state[row][col], size=8) for row in range(4)]
        t = []
        for row in range(4):
            new_val = BitVector(intVal=0, size=8)
            for k in range(4):
                # Use inverse MixColumns matrix
                product = InvMixer[row][k].gf_multiply_modular(column[k], AES_modulus, 8)
                new_val ^= product
            t.append(int(new_val.get_bitvector_in_hex(), 16))
        result.append(t)
    
    # Transpose to match original state format
    return [[result[row][col] for row in range(4)] for col in range(4)]


def makeDecimals(words):
    for i in range(0, len(words)):
            words[i] = int(words[i], 16)
    return words

def genRandomInitialVector():
    v = []
    for i in range (0,4):
        temp = []
        for j in range (0,4):
            temp.append(random.randint(0,255))
        v.append(temp)
    return v

def encrypt(user_key, user_plainText):
    # print('Hex: ', end='')
    key_hex = []
    for c in user_key:
        # print(hex(ord(c)), end=' ')
        key_hex.append(hex(ord(c)))
    # print("user key:" , user_key)
    # print('user key in hex: ' , end='')
    # for i in range (0, len(key_hex)):    
    #     print(key_hex[i], end=' ')
    # print('\n')
    start_time = time.perf_counter()
    key_hex = key_schedule(user_key)
    end_time = time.perf_counter()
    # print('Time taken for key schedule encryption: ', end_time - start_time, 'ms')
    # print('key hex in encryption: ',key_hex)

    key_hex_blocks = []
    for i in range (0, len(key_hex), 4):
        one_block = (key_hex[i:i+4])
        key_hex_blocks.append(one_block)
    # print(type(key_hex_blocks[0][0][0]))
    # print('len=', len(key_hex_blocks))
    # print('key_hex_blocks:', key_hex_blocks)
    # print('\n')
    # key_schedule(user_key)
    # print('user plain text: ' , user_plainText)
    user_plainText_Hex = makeHex(user_plainText)

    # print('user plain text in hex: ' , end='')
    # for i in range (0, len(user_plainText_Hex),):  
    #     print(user_plainText_Hex[i], end=' ')
    # print('\n')


    user_plainText_Hex = padding_Process(user_plainText_Hex)
    # print(user_plainText_Hex)
    newstring = ''
    for i in range (0, len(user_plainText_Hex)):
        newstring += (chr(int(user_plainText_Hex[i],16))) # chr(user_plainText_Hex[i])
    # print('user plain text after padding: ' , newstring)
    # print('user plain text after padding in hex: ' , end='')
    # for i in range (0, len(user_plainText_Hex)):
    #     print(user_plainText_Hex[i], end=' ')
    # print('\n')
    # print(user_plainText_Hex)
    R = 10
    blocks = []
    # print('klength of userplaintext afer padding: ', len(user_plainText_Hex))
    for i in range (0, len(user_plainText_Hex), 16):
        
        one_block = []
        for j in range (0, 16, 4):
            one_block.append(user_plainText_Hex[i+j:i+j+4])
        blocks.append(one_block)

    for i in range (0, len(blocks)):
        for j in range(0, 4):   
            blocks[i][j] = makeDecimals(blocks[i][j])
    # print('blocks before iv :', blocks, end='\n\n')
    iv = genRandomInitialVector()
    tempiv = iv.copy()
    blocks.insert(0, iv)
    for i in range (1, len(blocks)):
        for j in range(0, 4):
            # print('blokcs i j L:' , blocks[i][j])
            blocks[i][j] = xor_lists(blocks[i][j], blocks[i-1][j])
     
    # print('blocks after iv: ',  blocks)
    # print('iv: ', tempiv)
    

    key_for_round = key_hex_blocks[0]
    
    for i in range (0, len(key_hex_blocks)):
        for j in range(0, 4):
            key_hex_blocks[i][j] = makeDecimals(key_hex_blocks[i][j])
    # print('blocks:', blocks, end='\n\n')
    # print('key hex blocks:', key_hex_blocks, end='\n\n')
    for blockno in range (0, len(blocks)):
            block = blocks[blockno]
            cipherText = block
            for i in range (0,4):
                # cipherText[i] = makeDecimals(cipherText[i])
                cipherText[i] = xor_lists(cipherText[i], key_for_round[i])
            blocks[blockno] = cipherText
    # print(cipherText)

    ciphered_blocks = []
    for _i in range (0, 10):
        key_for_round = key_hex_blocks[_i + 1]
        for blockno in range (0, len(blocks)):
            block = blocks[blockno]
            cipherText = block
            cipherText = subBytes(cipherText)
            # print('After subbytes:' , cipherText)
            for j in range (0,4):
                cipherText[j] = leftRotateWord(cipherText[j])
            # print('After leftRotateWord:' , cipherText)
            if (_i < 9):
                cipherText = mix_columns(cipherText)
                # print('After mix_columns:' , cipherText)
            for i in range (0,4):
                # cipherText[i] = makeDecimals(cipherText[i])
                # key_for_round[i] = makeDecimals(key_for_round[i])
                cipherText[i] = xor_lists(cipherText[i], key_for_round[i])
            blocks[blockno] = cipherText
            # print('encryption turn no: ', _i + 1, ' :: cipher: ' , cipherText)
        
    ans = ''
    for i in range (0, len(blocks)):
        for j in range(0, 4):
            for k in range(0, 4):
                ans += chr(blocks[i][j][k])
    return ans 
# print(blocks)


def decrypt(user_key, encrypted_text):
    # print('Hex: ', end='')
    # print('blokcs in decryption:', blocks)
    key_hex = []
    for c in user_key:
        # print(hex(ord(c)), end=' ')
        key_hex.append(hex(ord(c)))
    start_time = time.perf_counter()
    key_hex = key_schedule(user_key)
    end_time = time.perf_counter()
    # print('key_schedule time for decryption: ', end_time - start_time)
    # print(key_hex)

    encrypted_text = makeHex(encrypted_text)
    # for i in range (0, len(encrypted_text)):    
    #     print(encrypted_text[i], end=' ')
    # print()
    # print(user_plainText_Hex)
    R = 10
    blocks = []
    for i in range (0, len(encrypted_text), 16):
        
        one_block = []
        for j in range (0, 16, 4):
            one_block.append(encrypted_text[i+j:i+j+4])
        blocks.append(one_block)
    for i in range (0, len(blocks)):
        for j in range(0, 4):   
            blocks[i][j] = makeDecimals(blocks[i][j])

    key_hex_blocks = []
    for i in range (0, len(key_hex), 4):
        one_block = (key_hex[i:i+4])
        key_hex_blocks.append(one_block)
    # print(type(key_hex_blocks[0][0][0]))
    for i in range (0, len(key_hex_blocks)):
        for j in range(0, 4):
            key_hex_blocks[i][j] = makeDecimals(key_hex_blocks[i][j])
    # print('key_hex_blocks in decryption:', key_hex_blocks)
    # Reverse the round keys (for decryption)
    reversed_round_keys = key_hex_blocks[::-1]  # Start from last round key

    # Start with the last round (no inverse mix_columns)
    for blockno in range(len(blocks)):
        block = blocks[blockno]
        decrypted_block = block

        # Round 10 (first in decryption)
        key_for_round = reversed_round_keys[0]  # Last encryption round key
        for i in range(4):
            decrypted_block[i] = xor_lists(decrypted_block[i], key_for_round[i])
        # print('Round 10: ', decrypted_block)
        # Inverse ShiftRows (right rotate)
        for j in range(4):
            decrypted_block[j] = invLeftRotateWord(decrypted_block[j])  # New helper function
        # print('After Inverse ShiftRows: ', decrypted_block)
        # Inverse SubBytes
        decrypted_block = invSubBytes(decrypted_block)
        # print('After Inverse SubBytes: ', decrypted_block)
        blocks[blockno] = decrypted_block

    # Rounds 9 to 1 (with inverse mix_columns)
    for _i in range(1, 10):
        key_for_round = reversed_round_keys[_i]
        for blockno in range(len(blocks)):
            block = blocks[blockno]
            decrypted_block = block

            # AddRoundKey
            for i in range(4):
                decrypted_block[i] = xor_lists(decrypted_block[i], key_for_round[i])
            # print('Round ', _i, ': ', decrypted_block)
            # Inverse MixColumns
            decrypted_block = invMixColumns(decrypted_block)
            # print('After Inverse MixColumns: ', decrypted_block)
            # Inverse ShiftRows
            for j in range(4):
                decrypted_block[j] = invLeftRotateWord(decrypted_block[j])
            # print('After Inverse ShiftRows: ', decrypted_block)
            # Inverse SubBytes
            decrypted_block = invSubBytes(decrypted_block)
            # print('After Inverse SubBytes: ', decrypted_block)
            blocks[blockno] = decrypted_block

    # Final round (Round 0)
    key_for_round = reversed_round_keys[10]  # Original key
    for blockno in range(len(blocks)):
        block = blocks[blockno]
        decrypted_block = block
        for i in range(4):
            decrypted_block[i] = xor_lists(decrypted_block[i], key_for_round[i])
        blocks[blockno] = decrypted_block
    
    
    alloutput = []
    # print('finally cdecryprd blokcs : ' , blocks)
   
    i = len(blocks) - 1
    while(i > 0):
        for j in range(0,4):
            blocks[i][j] = xor_lists(blocks[i][j], blocks[i-1][j])
        i -= 1
            
    # print('all bnlokcs in decryption: ' , blocks)
    blocks = blocks[1: ]
    for i in range (0, len(blocks)):
        for j in range (0, 4):
            for k in range (0, 4):
                alloutput.append(blocks[i][j][k])
    cut = alloutput[len(alloutput)-1]
    # print('Before unpadding')
    # print('in hex: ' , alloutput)
    ans = ''
    for i in range (0, len(alloutput)):
        ans += chr(alloutput[i])
    # print('in ASCII: ' , ans)
    while cut > 0:
        cut -= 1
        alloutput.pop()
    
    ans = ''
    for i in range (0, len(alloutput)):
        ans += chr(alloutput[i])
    # print('After unpadding')
    # print('in hex: ' , alloutput)
    # print('in ASCII: ' , ans)
    return ans 



def inverse_mod(k, p):
    return pow(k, -1, p)

def point_add(P1, P2, a, P):
    if P1 is None:
        return P2
    if P2 is None:
        return P1
    x1, y1 = P1
    x2, y2 = P2

    if x1 == x2 and (y1 + y2) % P == 0:
        return None  # Point at infinity

    if P1 != P2:
        s = ((y2 - y1) * inverse_mod(x2 - x1, P)) % P
    else:
        s = ((3 * x1 * x1 + a) * inverse_mod(2 * y1, P)) % P

    x3 = (s * s - x1 - x2) % P
    y3 = (s * (x1 - x3) - y1) % P

    return (x3, y3)

def scalar_mult(k, point, a, P):
    result = None
    addend = point

    while k:
        if k & 1:
            result = point_add(result, addend, a, P)
        addend = point_add(addend, addend, a, P)
        k >>= 1
    return result


def isQuardraticResidue(n, p):
    return pow(n, (p - 1) // 2, p) == 1

def tonelliShanksAlgorithm(n, p):
    #  checking the euler's criterion for p
    if isQuardraticResidue(n, p) == False:
        return None  # n is not a quadratic residue
    
   
    Q = p - 1
    S = 0
    while Q % 2 == 0:
        Q //= 2 # factoring out Q until Q is an odd number
        S += 1 # we need to multiply Q with 2 to the power s
    # we have a situation where p - 1 = Q * 2^s

    z = 2 # checking whether z is a quadratic residue, increasing the value of z until we find it
    while pow(z, (p - 1) // 2, p) != p - 1:
        z += 1
    
    
    M = S
    c = pow(z, Q, p)
    t = pow(n, Q, p)
    R = pow(n, (Q + 1) // 2, p)
    
    
    while True:
        if t == 0:
            return 0 # if t's value is 0, return 0
        if t == 1:
            return R #if t's value is 1, return R
        # otherwise we will use repeated squaring
        # to find the least i, 0 < i < M, such that t^(2^i) ≡ 1 mod p
        i = 0
        temp = t
        while temp != 1 and i < M:
            temp = pow(temp, 2, p) # to find the lowest i possible to ge the t^(2^i) ≡ 1 mod p
            i += 1
        if i == M:  # No solution exists, so return None
            return None
        b = pow(c, 2**(M - i - 1), p)
        M = i
        c = pow(b, 2, p)
        t = (t * c) % p
        R = (R * b) % p

def find_base_point(a, b, P):
    while True:
        x = randint(0, P-1)
        y_squared = (x**3 + a*x + b) % P

        # Euler's criterion: y² is a quadratic residue mod P
        if isQuardraticResidue(y_squared, P) == True:
            try:
                y = tonelliShanksAlgorithm(y_squared, P)
                return (x, y)
            except:
                continue  # If Tonelli–Shanks fails, try another x

def ecc(k):
    # Step 1: Generate curve parameters
    
    P = randprime(2 ** (k- 1), 2 ** (k))
    # print('randprime: ', P)
    a = randint(0, P-1)
    b = randint(0, P-1)
    while (4 * a**3 + 27 * b**2) % P == 0:
        a = randint(0, P-1)
        b = randint(0, P-1)

    # print('a, b: ', a, b)
    G = find_base_point(a, b, P)

    # geenrate a rendom key for Alice 
    start_time = time.perf_counter()
    Ka = randint(1, P-1)
    A = scalar_mult(Ka, G, a, P)
    end_time = time.perf_counter()
    # print('', end_time - start_time, 'ms', end=' : ')

    # Generate a random key for Bob
    start_time = time.perf_counter()
    Kb = randint(1, P-1)
    B = scalar_mult(Kb, G, a, P)
    end_time = time.perf_counter()
    # print('', end_time - start_time, 'ms' , end=' : ')

    start_time = time.perf_counter()
    #Alice get the bob's key B, and then calculating the shared key
    R_alice = scalar_mult(Ka, B, a, P)
    end_time = time.perf_counter()
    # print('', end_time - start_time, 'ms', end=' : ')
    # Bob get the alice's key A, and then calculating the shared key
    R_bob = scalar_mult(Kb, A, a, P)

    assert R_alice == R_bob # Checking to make sure that both sides of the equation are equal so that alice and bob get the same key, otherwisre the algorithm is not working

    aes_key = R_alice[0].to_bytes((k + 7) // 8, 'big')[:k//8]
    # print("AES Key:", aes_key.hex())
    # print('AES Key length: ', aes_key)
    ans_key = ''
    for i in range(0, len(aes_key)):
        ans_key += chr(aes_key[i])
    # print('ANS Key: ', ans_key)
    # print(len(aes_key))


import socket			

def client():

    # Create a socket object 
    s = socket.socket()         
    
    # Define the port on which you want to connect 
    port = 12345  
    k = 128
    s.connect(('127.0.0.1', port))  
    a,b,G,P,A,Ka = ecc(128)
    params  = {
        'a': a,
        'b': b,
        'G': G,
        'P': P,
        'A': A
    }
    s.send(json.dumps(params).encode('utf-8'))
    data = s.recv(1024).decode()
    params = json.loads(data)
    B = params['B']
    
    # print('B:' , B)
    
    R_alice = scalar_mult(Ka, B, a, P)
    aes_key = R_alice[0].to_bytes((k + 7) // 8, 'big')[:k//8]
    # print("AES Key:", aes_key.hex())
    # print('AES Key length: ', aes_key)
    ans_key = ''
    for i in range(0, len(aes_key)):
        ans_key += chr(aes_key[i])
    
    print('ANS Key: ', ans_key)

    while True:
        # connect to the server on local computer 
        
        msg = input('Write message:')
        if(msg == 'exit'):
            break
        s.send(msg.encode('utf-8'))
        # receive data from the server and decoding to get the string.
        print ('Receiver message from server : ',s.recv(1024).decode())
        # close the connection 
    s.close()   


def server():
    s = socket.socket()		 
    print ("Socket successfully created")
    port = 12345			
    s.bind(('', port))		 
    print ("socket binded to %s" %(port)) 
    s.listen(5)	 
    print ("socket is listening")		 
    c, addr = s.accept()	
    data = c.recv(1024*5).decode()
    params = json.loads(data)
    a,b,G,P,A = params['a'],params['b'],params['G'],params['P'],params['A']
    k = 128
    # print(a ,b,G,P,A , ' : in the server')
    Kb = randint(1, P-1)
    B = scalar_mult(Kb, G, a, P)
    params = {
        'B': B
    }
    c.send(json.dumps(params).encode('utf-8'))
    R_bob = scalar_mult(Kb, A, a, P)

    aes_key = R_bob[0].to_bytes((k + 7) // 8, 'big')[:k//8]
    # print("AES Key:", aes_key.hex())
    # print('AES Key length: ', aes_key)
    ans_key = ''
    for i in range(0, len(aes_key)):
        ans_key += chr(aes_key[i])
    
    print('user Key: ', ans_key)
    user_key = ans_key
    for i in range (0,16):
        user_key += '0'
    more = len(user_key) - 16
    while more > 0:
        more-=1
        user_key = user_key[0:len(user_key)-1]
    while True: 

        
        print ('Got connection from', addr )
        received = c.recv(1024).decode()
        print('Received plaintext from client :', received)
        decryptedText = decrypt( user_key, received)
        print('Decrypted message from client :', decryptedText)
        # msg = input("Write your reply : ")
        # c.send(msg.encode()) 
        # if(msg == 'exit'):
        #     break   
        

    c.close()
    s.close()
server()
