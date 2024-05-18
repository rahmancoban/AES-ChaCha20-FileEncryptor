import subprocess
import tkinter as tk
from tkinter import filedialog, simpledialog, messagebox

# Define a function to run the selected cryptographic program with provided inputs.
def run_program(program, filepath, mode):
    if program == 'rsa':
        n = simpledialog.askinteger("RSA", "Enter the modulus n (product of two primes):", parent=root)
        if n is None:
            messagebox.showerror("Error", "Modulus n is required for RSA.")
            return
        exp_label = "Enter the public exponent e for encryption:" if mode == 'encrypt' else "Enter the private exponent d for decryption:"
        exp = simpledialog.askinteger("RSA", exp_label, parent=root)
        if exp is None:
            messagebox.showerror("Error", "Exponent is required for RSA.")
            return
        subprocess.run(['./rsa', filepath, str(n), str(exp), mode])
    elif program == 'aes':
        key = simpledialog.askstring("AES Key", "Enter the 16-byte key for AES operation (exactly 16 characters):", parent=root)
        if key:
            print(f"Key length: {len(key)}")
            if len(key) == 16:
                subprocess.run(['/Users/rahmancoban/D/marmara/zErasmus/Romanya/4.Semester (24:Spr)/Security And Criptoraphy/abdurrahman_coban_2/aes', filepath, key, mode])
            else:
                messagebox.showerror("Error", "Key must be exactly 16 characters long.")
    elif program == 'chacha20':
        key = simpledialog.askstring("ChaCha20 Key", "Enter the 32-byte key for ChaCha20 operation (exactly 32 characters):", parent=root)
        nonce = simpledialog.askstring("ChaCha20 Nonce", "Enter the 8-byte nonce for ChaCha20 operation (exactly 8 characters):", parent=root)
        if key and nonce:
            print(f"Key: {key}, Key length: {len(key)}")
            print(f"Nonce: {nonce}, Nonce length: {len(nonce)}")
            if len(key) == 32 and len(nonce) == 8:
                subprocess.run(['/Users/rahmancoban/D/marmara/zErasmus/Romanya/4.Semester (24:Spr)/Security And Criptoraphy/abdurrahman_coban_2/chacha20', filepath, key, nonce, mode])
            else:
                messagebox.showerror("Error", "Key must be exactly 32 characters long and nonce must be exactly 8 characters long.")
    else:
        messagebox.showerror("Error", "Unsupported algorithm selected.")

# Function to open a file selection dialog.
def select_file():
    return filedialog.askopenfilename()

# Function to handle encrypt or decrypt actions.
def encrypt_or_decrypt(mode):
    program = program_var.get()
    filepath = select_file()
    if filepath:
        run_program(program, filepath, mode)

# Setup the main window of the application using tkinter.
root = tk.Tk()
root.title("Cryptography GUI")

program_var = tk.StringVar(value="RSA")
options = {'AES': "aes", 'ChaCha20': "chacha20", 'RSA': "rsa"}
for text, value in options.items():
    tk.Radiobutton(root, text=text, variable=program_var, value=value).pack(anchor=tk.W)

tk.Button(root, text="Encrypt File", command=lambda: encrypt_or_decrypt('encrypt')).pack(side=tk.LEFT, padx=10, pady=10)
tk.Button(root, text="Decrypt File", command=lambda: encrypt_or_decrypt('decrypt')).pack(side=tk.LEFT, padx=10, pady=10)

root.mainloop()
