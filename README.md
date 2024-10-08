# README for Cryptographic Tool

## Overview
This tool is designed to provide robust cryptographic functionalities, including AES, ChaCha20, and RSA algorithms. It allows users to perform encryption and decryption on various types of data, including text and files, through a command-line interface. 

## Features
- Support for AES (with modes ECB, CBC, CTR, GCM), ChaCha20, and RSA algorithms.
- Encryption and decryption capabilities for both textual data and files.
- Secure key, nonce, and IV handling for different cryptographic modes.


## Requirements
- Python environment (Preferably Python 3.6 or higher)
- Required Python libraries: `secrets`, `hashlib`, `mimetypes`, `json`, `logging`, `tqdm`
- Operating System: Windows, Linux, or macOS

## Installation
1. Clone the repository or download the source code.
2. Ensure Python is installed on your system.
3. Navigate to the tool's directory and run the Python script.

   ```bash
   python main.py [arguments]
   ```

## Usage
The tool is executed via command-line interface. Below are the available commands and options:

```
python main.py -a [ALGORITHM] -M [MODE] -p [FILE_PATH] -m [MESSAGE] -k [KEY] -n [NONCE] -iv [IV] -j [JSON_PATH] -d
```

- `-a`, `-algorithm`: Choose between `AES`, `RSA`, `ChaCha20`
- `-M`, `-mode`: Select mode (only for AES) - `CTR`, `GCM`, `CBC`, `ECB`
- `-d`, `-decryption`: Use this flag to perform decryption
- `-k`, `-key`: Path to the key file or the key's numerical value (for decryption)
- `-n`, `-nonce`: Specify nonce value (for decryption in AES CTR)
- `-iv`: Specify IV (Initialization Vector) value (for decryption in AES CBC)
- `-j`: Specify the json file generated during encryption (for decryption)
- `-p`, `-path`: Specify the file path for file encryption/decryption
- `-m`, `-message`: Specify the message for direct text encryption/decryption

## Examples
Encrypt a file using AES in CBC mode:
```bash
python main.py -a AES -M CBC -p path/to/file
```

## Logging
- Logs are stored in the `history` directory, which is automatically created.
- Log files provide a record of operations, errors, and other important information.




