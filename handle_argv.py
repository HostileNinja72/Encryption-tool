import argparse
from ansi import * 

def handle_argv():
    parser = argparse.ArgumentParser(description="Encryption Tool")

    parser.add_argument('-a', '-algorithm', choices=['AES', 'RSA', 'ChaCha20'], help= "Select algorithm")
    parser.add_argument('-M', '-mode', choices=['CTR', 'GCM', 'CBC', 'ECB'], help="Select mode (CBC, CTR, GCM, ECB)" + yellow + " for AES ONLY" + RESET)
    parser.add_argument('-d', '-decryption', action='store_true', help="Flag for decryption")
    parser.add_argument('-k', '-key', help="Path to the key (must be a .txt file) or its numerical value" + yellow + " (ONLY use it in Decryption)" + RESET)
    parser.add_argument('-n', '-nonce', help="Specify nonce value" + yellow + " (ONLY use it in Decryption)" + RESET)
    parser.add_argument('-iv', help="Specify IV (Initialization Vector) value" + yellow + " (ONLY use it in Decryption)" + RESET)
    parser.add_argument('-j', help="Specify the json file (that was generated during the encryption process) for the" + yellow +" Decryption" + RESET)

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-p', '-path', help="Specify file path")
    group.add_argument('-m', '-message', help="Specify user input")

    args = parser.parse_args()

    if args.M and args.a != "AES":
        print("Modes are ONLY available for AES")
        exit(1)

    if args.a == "RSA":
        if not args.m:
            print("Please enter a message to decrypt")
            exit(1)
    if args.a == 'AES': #if the algorithm chosend is AES
        if not args.M:
            print("Please choose a mode for AES (CTR, CBC, GCM, ECB).")
            exit(1)
        if args.M not in ['CTR', 'CBC', 'GCM', 'ECB']: # Make sure the algorithm chosing is valid
            print("Invalid mode for AES. Please choose 'CTR', 'CBC', 'GCM', or 'ECB'.")
            exit(1)

        if args.d: # if the decryption flag is true
            if args.j:
                print("You have entered the path to the json file")
            elif args.k == None: #check if the key is given
                print("Please give the key for the decryption !")
                exit(1)
            elif ".txt" in args.k:
                print("You have entered the path to the key")
            elif len(args.k) != 32: #Check the length of the key
                print("The key must be 128 bits (32 hex characters) long.") 
                exit(1)
            elif args.M == 'CTR': #make sure the iv or nonce is there on a 128 bits size
                if args.n is None:
                    print("Please enter the nonce value for your AES CTR decryption.")
                    exit(1)
                elif len(args.n) != 32:  # 128 bits = 16 bytes = 32 hex characters
                    print("Nonce must be 128 bits (32 hex characters) long.")
                    exit(1)
            elif args.M == 'CBC':
                if args.iv is None:
                    print("Please enter the IV value for your AES CBC decryption.")
                    exit(1)
                elif len(args.iv) != 32:  # 128 bits = 16 bytes = 32 hex characters
                    print("IV must be 128 bits (32 hex characters) long.")
                    print("If you are entering the path to the key please make sure the file has a .txt extention")
                    exit(1)
            
    if not args.d:
        if args.j or args.n or args.iv or args.k:
            print("You can't specify a json, a key, or a iv value in encryption mode, run -h for help")
            exit(1)
        

    if args.m and args.p: # a user must not enter the path and message in the same time
        print("You can't encrypt a message and a file at the same time!")
        exit(1)

    return args.a, args.M, args.m, args.p, args.k, (bytes.fromhex(args.n) if args.n else None), (bytes.fromhex(args.iv) if args.iv else None), args.d, args.j

if __name__ == "__main__":
    handle_argv()
