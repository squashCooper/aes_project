#this program uses the Advanced Encryption Standard in order to 
#encrypt a user entered file 
#author: Tori Cooper





#standard S-Box 
sbox = [
        0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01,   0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
        0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
        0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
        0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
        0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
        0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
        0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
        0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
        0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
        0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
        0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
        0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
        0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
        0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
        0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
        0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
]

#will use for decryption 
sboxInv = [
         0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
         0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
         0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
         0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
         0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
         0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
         0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
         0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
         0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
         0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
         0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
         0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
         0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
         0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
         0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
         0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
] 

#mixed columns matrix 

mixed_columns_matrix = [
    [0x02, 0x03, 0x01, 0x01],
    [0x01, 0x02, 0x03, 0x01],
    [0x01, 0x01, 0x02, 0x03],
    [0x03, 0x01, 0x01, 0x02]
]

#inverse mized columns 

inv_mixed_columns_matrix = [
    [0x0e, 0x0b, 0x0d, 0x09],
    [0x09, 0x0e, 0x0b, 0x0d],
    [0x0d, 0x09, 0x0e, 0x0b],
    [0x0b, 0x0d, 0x09, 0x0e]
]
#10 digits bc 128 bit encryption
#round constants for key expansion 
rcon = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36]


#takes file, reads it in binary, returns file contents 

def read_file(filename):
    with open(filename, 'rb') as file: 

        print("reading contents of file")
        file_contents = file.read()
      

      #  filename.close()
    return file_contents

def sub_bytes(state):
 #first 4 bits are in a row
    #print("sub bytes beginning ")
    result = [[0 for _ in range(4)] for _ in range(4)]
    for i in range(4):
    #second 4 bits are in a column
       for j in range(4):
            value = state[i][j]
            result[i][j] = sbox[value]
         #   print(result[i][j])
    

    #gets output of s box 
    return result
def inv_sub_bytes(state):
   #  print("inv sub bytes beginning: ")
    result = [[0 for _ in range(4)] for _ in range(4)]
    for i in range(4):
        for j in range(4):
            value = state[i][j]
            result[i][j] = sboxInv[value]
          #  print(result[i][j])
    return result



#def inv_sub_bytes(state):
# 
#    for i in range(4):
#        for j in range(4):
#            state[i][j] = sboxInv[state[i][j]]
#    return state

#out shift_rows: is a 4 x 4 matrix w/ entries in 4x4 matrix c_i,j
def shift_rows(state):
    #print("in shift rows: current state", state, "\n")
    result = [[0 for _ in range(4)] for _ in range(4)]

  
    for j in range(4):
        #no shift 
        result[0][j] = state[0][j]
        #shift by 1 
        result[1][j] = state[1][(j + 1) % 4]
        #shift by 2 
        result[2][j] = state[2][(j + 2) % 4]
        #shift by 3 
        result[3][j] = state[3][(j + 3) % 4]
    
   # print("state after shift rows:", result, "\n")
    return result

def shift_rows_inverse(state):
  #  print("in inverse shift rows: current state", state, "\n")
    result = [[0 for _ in range(4)] for _ in range(4)]
    
    for j in range(4):
        #no shift 
        result[0][j] = state[0][j]
        #shift right by 1 
        result[1][j] = state[1][(j - 1) % 4]
        #shift right by 2 
        result[2][j] = state[2][(j - 2) % 4]
        #shift right by 3 
        result[3][j] = state[3][(j - 3) % 4]
    
  #  print("state after inverse shift rows:", result, "\n")
    return result



def rotate_word(w):
    #print("rotating word", w, "\n")
    w <<= 1
    #print("rotated word", w)
    return w


def mix_columns(state):
    #print(" mix columns: current state", state, "\n")
    new_state = [[0 for _ in range(4)] for _ in range(4)]
    
    for j in range(4): #columns
        for i in range(4):  #rows
            val = 0
            for k in range(4):
                val ^= gf_multiply(mixed_columns_matrix[i][k], state[k][j])
            new_state[i][j] = val
    
   # print("state after mix columns:", new_state, "\n")
    return new_state

def mix_columns_inverse(state):
  #  print("in inverse mix columns: current state", state, "\n")
    new_state = [[0 for _ in range(4)] for _ in range(4)]
    
    for j in range(4):  #columns
        for i in range(4): #rows
            val = 0
            for k in range(4):
                val ^= gf_multiply(inv_mixed_columns_matrix[i][k], state[k][j])
            new_state[i][j] = val
    
   # print("state after inverse mix columns:", new_state, "\n")
    return new_state

#1. round constants 
#2. word size
#3. key schedule 
#4. expansion rounds
#  - rotate bytes in a word 
# - substitution operation using s box 
# - r con xors using round constant 
# round keys : order of round keys that are still in place after
#all expansion rounds defines ket schedule
#round key is xored with new state from mix colums 


def gf_multiply(a, b):
    p = 0
    for i in range(8):
        if b & 1:
            p ^= a
        high_bit_set = a & 0x80
        a = (a << 1) & 0xFF
        if high_bit_set:
            a ^= 0x1B  # irreducible polynomial 
        b >>= 1
    return p 

#round key function: single initial key expanded into a series of round keys 
def add_round_key(state, round_key):
   # print("in add round key ")
    result = [[0 for _ in range(4)] for _ in range(4)]
    
    for i in range(4):
        for j in range(4):
            result[i][j] = state[i][j] ^ round_key[i][j]
    
    return result



def key_expansion(key):
    #convert key to a list of bytes
    key_bytes = list(key)
  #  print("original key bytes", key_bytes)
    
    # initialize expanded key with the original key
    expanded_key = key_bytes.copy()
  #  print(" expanded key:", expanded_key)
    
    #16 byte key 
    key_size = 16 
    rcon_index = 0
    
    # initial temp value 
    temp = expanded_key[key_size-4:key_size].copy()
    #print("initial temp:", temp)
    
    #10 round keys after initial key 
    for i in range(1, 11): 
     #   print(f"round key {i} generation:")
        
        #rotate
        temp = temp[1:4] + temp[0:1]
       # print("after rotation:", temp)
        #s box
        for j in range(4):
        #    print(f"substituting byte {j}")
            temp[j] = sbox[temp[j]]
        #print("after substitution:", temp)
        
        # xor 
        temp[0] ^= rcon[rcon_index]
       # print(f"xor with rcon[{rcon_index}]:", temp)
        rcon_index += 1
        
        

        for j in range(4):
            for k in range(4):
                next_byte = expanded_key[len(expanded_key) - key_size + k] ^ temp[k]
                expanded_key.append(next_byte)
            
            if j < 3:  # dont update for last iteration 
                temp = expanded_key[-4:].copy()
             #   print(f"temp for next word: {temp}")
        
        # break if enough bytes have been made
        if len(expanded_key) >= (11 * 16):  
          #  print("key material generated)
            break
    
    # convert to 11 round keys in matrix format 
    round_keys = []
    for r in range(11):
        # extract 16 bytes
        key_slice = expanded_key[r*16:(r+1)*16]
        
        # convert to matrix: column major order 
        matrix = [[0 for _ in range(4)] for _ in range(4)]
        for row in range(4):
            for col in range(4):
                matrix[row][col] = key_slice[row + 4*col]
        
        round_keys.append(matrix)
    
   # print(f"generated {len(round_keys)} round keys")
    return round_keys


def encrypt_block(state, round_keys):

    # copy of state 
    state = [[state[i][j] for j in range(4)] for i in range(4)]
    
    # first round
    state = add_round_key(state, round_keys[0])
    

    for round_num in range(1, 10):
        state = sub_bytes(state)
        state = shift_rows(state)
        state = mix_columns(state)
        state = add_round_key(state, round_keys[round_num])
    
    # final round, round keys will be at index 10 
    state = sub_bytes(state)
    state = shift_rows(state)
    state = add_round_key(state, round_keys[10])
    
    return state

def decrypt_block(state, round_keys):
 
 #similar to encrypt block, essentially the opposite
    state = [[state[i][j] for j in range(4)] for i in range(4)]
    
    # first round 
    state = add_round_key(state, round_keys[10])
    state = shift_rows_inverse(state)
    state = inv_sub_bytes(state)
    
    for round_num in range(9, 0, -1):
        state = add_round_key(state, round_keys[round_num])
        state = mix_columns_inverse(state)
        state = shift_rows_inverse(state)
        state = inv_sub_bytes(state)
    
    #now round keys will be at index 0 
    state = add_round_key(state, round_keys[0])
    
    return state

def encrypt_file(in_file, out_file, key):
   
   #read contents
    file_contents = read_file(in_file)
    
    # create round keys 
    round_keys = key_expansion(key)
    
    #reading in blocks of 16 bytes so figure out how much 
    #padding is necessary 
    padding_length = 16 - (len(file_contents) % 16)
    
    
    padded_data = file_contents + bytes([padding_length] * padding_length)
    
    # process each block 
    encrypted_data = bytearray()
    for i in range(0, len(padded_data), 16):
        # get 16 bytes
        block_bytes = padded_data[i:i+16]
        
        # convert to state matrix
        state = [[0 for _ in range(4)] for _ in range(4)]
        for j in range(16):
            row = j % 4
            col = j // 4
            state[row][col] = block_bytes[j]
        
        # encrypt 
        encrypted_block = encrypt_block(state, round_keys)
        
        #add the encrypted block to the result 
        for col in range(4):
            for row in range(4):
                encrypted_data.append(encrypted_block[row][col])
    
    # write to file 
    with open(out_file, 'wb') as file:
        file.write(encrypted_data)
    
    return True

#similar to encrypt file 
def decrypt_file(in_file, out_file, key):
    
    #read file
    file_contents = read_file(in_file)
    
    #generate round keys 
    round_keys = key_expansion(key)
    
    #process the blocks 
    decrypted_data = bytearray()
    for i in range(0, len(file_contents), 16):
        #get 16 bytes 
        block_bytes = file_contents[i:i+16]
        
        # convert to matrix
        state = [[0 for _ in range(4)] for _ in range(4)]
        for j in range(16):
            row = j % 4
            col = j // 4
            state[row][col] = block_bytes[j]
        
        # decrypt block 
        decrypted_block = decrypt_block(state, round_keys)
        
        #add decrypted block to the result 
        for col in range(4):
            for row in range(4):
                decrypted_data.append(decrypted_block[row][col])
    
    # remove padding
    if decrypted_data:
        padding_value = decrypted_data[-1]
    
        if padding_value <= len(decrypted_data):
                decrypted_data = decrypted_data[:-padding_value]
    
 
    with open(out_file, 'w', encoding='utf-8') as file:
            file.write(decrypted_data.decode('utf-8', errors='replace'))
 
    
    return True


    


#works on 16 byte blocks 

def convert_to_blocks(file_contents):
    #convert file to 16 byte blocks and return a list of 16 byte blocks
  
    # calculate padding length 
    padding_length = 16 - (len(file_contents) % 16)
    
    # padding bytes
    padded_data = file_contents + bytes([padding_length] * padding_length)
    
    # 16 byte blocks 
    blocks = []
    for i in range(0, len(padded_data), 16):
        block = padded_data[i:i+16]
        # convert to 4x4 matrix 
        state = [[0 for _ in range(4)] for _ in range(4)]
        # For encryption (in convert_to_blocks):
        for r in range(4):
            for c in range(4):
                state[r][c] = block[r + 4*c] 
        blocks.append(state)
    
    return blocks


if __name__ == "__main__":

    print("Make sure the file you would like to encrypt is in the same directory as this program\n")

    filename = input("Enter the name of the file that you would like to encrypt: \n")
    output_file = input("Enter the name of the file that will contain the encrypted output: \n")
    key = input("Enter a 16 character encryption key: ")

    if(len(key) != 16):
        while(len(key) != 16):
            print("Make sure the key is 16 characters \n")
            key = input("Enter a 16 character encryption key: \n")

    #convert key to bytes

    print("Converting key to bytes\n")
    key = key.encode('utf-8') 
    print(key)

    
    success = encrypt_file(filename, output_file, key)
    
    if success:
        print(f"File encrypted successfully and saved as {output_file}\n")
    else:
        print("Encryption failed \n")

    user_wants_to_decrypt = input("Would you like to decrypt the file? Y/N \n")

    if(user_wants_to_decrypt == 'Y'):
        decryption_file = input("Enter the name of the file that you would like to decrypt: \n")
        d_output_file = input("Enter the name of the file that will contain the decrypted output: \n")

        decrypt_key = input("Enter a 16 character encryption key: \n")

        if(len(decrypt_key) != 16):
            while(len(decrypt_key) != 16):
                print("Make sure the key is 16 characters")
                decrypt_key = input("Enter a 16 character encryption key: ")
        print("Converting key to bytes")
        decrypt_key = decrypt_key.encode('utf-8') 
        print(decrypt_key)

        decryption_success = decrypt_file(decryption_file, d_output_file, decrypt_key)
    
        if decryption_success:
            print(f"File decrypted successfully and saved as {d_output_file}")
        else:
            print("Encryption failed")

    else:
        print("Ok")
   
