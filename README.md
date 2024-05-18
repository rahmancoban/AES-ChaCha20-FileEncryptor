# AES-ChaCha20-FileEncryptor

## Overview

AES-ChaCha20-FileEncryptor is a C-based cryptographic tool that provides encryption and decryption functionalities using two modern symmetric key algorithms: AES (Advanced Encryption Standard) and ChaCha20. The tool also includes a GUI built with Python's Tkinter for ease of use.

## Features

- **AES Encryption/Decryption**: Encrypt and decrypt files using AES-128.
- **ChaCha20 Encryption/Decryption**: Encrypt and decrypt files using ChaCha20.
- **User-Friendly GUI**: Simple and intuitive interface for file encryption and decryption.
- **Command Line Interface**: Option to use the tool via the command line for advanced users.

## Installation

### Prerequisites

- C Compiler (e.g., `gcc`)
- Python 3.x
- Tkinter (usually included with Python)

### Compilation

1. Compile the AES and ChaCha20 C programs:
   ```sh
   gcc -o aes aes.c
   gcc -o chacha20 chacha20.c
   ```

## Usage

### GUI Mode

1. Run the Python GUI:
   ```sh
   python3 crypto_gui.py
   ```
2. Select the encryption algorithm (AES or ChaCha20).
3. Choose a file to encrypt/decrypt.
4. Enter the required key and nonce (for ChaCha20).
5. Click "Encrypt File" or "Decrypt File".

### Command Line Mode

#### AES

- **Encrypt**:
  ```sh
  ./aes aes.txt 1234567890abcdef encrypt
  ```
- **Decrypt**:
  ```sh
  ./aes aes.txt 1234567890abcdef decrypt
  ```

#### ChaCha20

- **Encrypt**:
  ```sh
  ./chacha20 chacha20.txt 12345678901234567890123456789012 12345678 encrypt
  ```
- **Decrypt**:
  ```sh
  ./chacha20 chacha20.txt 12345678901234567890123456789012 12345678 decrypt
  ```

## Project Structure

- `aes.c`: Implementation of AES encryption and decryption.
- `chacha20.c`: Implementation of ChaCha20 encryption and decryption.
- `crypto_gui.py`: Python script for the graphical user interface.
- `README.md`: Project documentation.

## Acknowledgements

This project is developed for educational purposes to demonstrate the implementation of modern symmetric encryption algorithms in C and Python.
