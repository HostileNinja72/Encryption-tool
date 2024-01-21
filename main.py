from Algorithms.aes import AES
import time, secrets
from handle_argv import handle_argv
import mimetypes
import os
import hashlib
import json


RESET = "\033[0m"
green = "\u001b[32m"

def filetype_handler(type):
    return type.split('/')[1]
    
#Generate a secure random 128 bits key
def generate_random_key():
    return secrets.token_bytes(16)

def compute_file_hash(file_path):
    hasher = hashlib.sha256()
    with open(file_path, 'rb') as file:
        buffer_size = 65536  # 64 KB
        while chunk := file.read(buffer_size):
            hasher.update(chunk)
    return hasher.hexdigest()

def extract_file_metadata(file_path):
    file_name = os.path.basename(file_path)
    file_type, _ = mimetypes.guess_type(file_path)
    file_size = os.path.getsize(file_path)

    metadata = {
        'filename': file_name,
        'filetype': file_type,
        'filesize': file_size,
        # Add more metadata fields as needed
    }

    return metadata

def write_bytes_to_file(data_bytes, output_path):
    with open(output_path, 'wb') as file:
        file.write(data_bytes)



def main():
    # Generating the key
    master_key = int(generate_random_key().hex(), 16)
    
    #handling the args
    algorithm, mode, user_input, path_to_the_plain, key, nonce, iv, dec, json_path =  handle_argv()
    
    output_directory = "output"
    os.makedirs(output_directory, exist_ok=True)
    if json_path:
        with open(json_path, 'r') as json_file:
            data = json.load(json_file)
            key = data["key"][2:]
            if mode == 'CTR' :
                nonce = int(data["iv or nonce"], 16)
                nonce = nonce.to_bytes((nonce.bit_length()+7) // 8, 'big')
            elif mode == "CBC":
                iv = int(data["iv or nonce"], 16) 
                iv = iv.to_bytes((iv.bit_length()+7) // 8, 'big') 
            type = data["metadata"]["filetype"]
    #If the user wish to use AES and encryption algorithm
    if algorithm == "AES":
        #aes object
    
        aes = AES(master_key, mode, nonce=nonce, iv=iv)
        # If user wants to encrypt
        if not dec:
            if user_input: # Handling the data format of the input, to byte and then to hex
                plaintext = user_input.encode('utf-8').hex()
            else: 
                # If user gives us the path to the file instead of a message
                with open(path_to_the_plain, 'rb') as file:
                    metadata = extract_file_metadata(path_to_the_plain)
                    text_data = file.read()
                # The plaintext is the hex of the file in question
                plaintext = text_data.hex()
                # computing the hash of the file
                original_file_hash = compute_file_hash(path_to_the_plain)
                print("Original File Hash:", original_file_hash)

                # Write the hash of the original file to a file in the output folder 
                '''original_file_hash_path = os.path.join(output_directory, "original_file_hash.txt")
                with open(original_file_hash_path, 'w') as hash_file:
                    hash_file.write(original_file_hash) '''


            #start timer to keep in track the time needed for encryption
            start_time = time.time()
            #Encryption
            ciphertext = aes.encrypt(int(plaintext, 16))
            encryption_time = (time.time() - start_time) * 1000
            #decrypted_text = aes.decrypt(ciphertext)

            metadata_and_key = {
                "metadata" : metadata,
                "hash": original_file_hash, 
                "key" :hex(master_key),
                "iv or nonce": aes.get_iv().hex() if aes.get_iv() is not None else None
            }


            # We write the encrypted hex into the file output.hex in the output folder
            output_file_path = os.path.join(output_directory, "output.hex")
            with open(output_file_path, 'w') as output_file:
                output_file.write(ciphertext.hex())

            # We write the key as well in the key.txt in the output folder
            '''key_file_path = os.path.join(output_directory, "key.txt")
            with open(key_file_path, 'w') as file:
                file.write(hex(master_key))'''
            json_file_path = os.path.join(output_directory, "metadata_and_key.json")
            with open(json_file_path, 'w') as json_file:
                json.dump(metadata_and_key, json_file, indent=2)
            print(green +"Master Key: 0x{:032x}".format(master_key) + RESET)
            print("Metadata, hash and key stored in", json_file_path)
            #print("Plaintext:  0x{:032x}".format(int(plaintext, 16)))
            #print("Ciphertext: " + ciphertext.hex())
            #print("Decrypted:  " + str(decrypted_text))

            print(f"Encryption Time: {encryption_time:.6f} milliseconds")
        if dec: #decryption
            if isinstance(key, str) and ".txt" in key:
                with open(key, 'r') as file:
                    key = int(file.read())
                    aes.set_key(key)
            else:
                aes.set_key(int(key, 16))

            if user_input:
                ciphertext = user_input
            else:
                output_file_path = os.path.join(output_directory, "output.hex")
                with open(output_file_path, 'r') as file:
                    ciphertext = file.read()
            
            start_time = time.time()
            decrypted_text = aes.decrypt(bytes.fromhex(ciphertext)) #!!!
            decryption_time = (time.time() - start_time) * 1000

            #with open("output_decrypted.hex", 'w') as output_file:
                #output_file.write(decrypted_text.hex()
            decrypted_output_file_path = os.path.join(output_directory, f"test1.{filetype_handler(type)}")
            write_bytes_to_file(decrypted_text, decrypted_output_file_path)

            #print(green +"Master Key: " + key + RESET)

            print(f"Decryption Time: {decryption_time:.6f} milliseconds")
            

            
if __name__ == "__main__":
     main()
