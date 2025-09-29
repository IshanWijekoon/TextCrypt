import tkinter as tk
from tkinter import ttk, scrolledtext

def vigenere(message, key, direction=1):
    key_index = 0
    alphabet = 'abcdefghijklmnopqrstuvwxyz'
    final_message = ''

    for char in message.lower():
        # Append any non-letter character to the message
        if not char.isalpha():
            final_message += char
        else:        
            # Find the right key character to encode/decode
            key_char = key[key_index % len(key)]
            key_index += 1

            # Define the offset and the encrypted/decrypted letter
            offset = alphabet.index(key_char)
            index = alphabet.find(char)
            new_index = (index + offset*direction) % len(alphabet)
            final_message += alphabet[new_index]
    
    return final_message

def encrypt(message, key):
    return vigenere(message, key)
    
def decrypt(message, key):
    return vigenere(message, key, -1)

class TextCryptGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("TextCrypt")
        self.root.geometry("600x500")
        self.root.resizable(True, True)
        
        # Create main frame
        main_frame = ttk.Frame(root, padding="20")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Configure grid weights for responsive design
        root.columnconfigure(0, weight=1)
        root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(1, weight=1)
        
        # Title label
        title_label = ttk.Label(main_frame, text="TextCrypt", 
                               font=('Arial', 16, 'bold'))
        title_label.grid(row=0, column=0, columnspan=2, pady=(0, 20))
        
        # Message input
        ttk.Label(main_frame, text="Enter your message:").grid(row=1, column=0, sticky=tk.W, pady=(0, 5))
        self.message_text = scrolledtext.ScrolledText(main_frame, height=8, width=50)
        self.message_text.grid(row=2, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(0, 15))
        
        # Buttons frame
        button_frame = ttk.Frame(main_frame)
        button_frame.grid(row=3, column=0, columnspan=2, pady=(0, 15))
        
        # Encrypt and Decrypt buttons
        self.encrypt_btn = ttk.Button(button_frame, text="Encrypt", command=self.encrypt_message)
        self.encrypt_btn.pack(side=tk.LEFT, padx=(0, 10))
        
        self.decrypt_btn = ttk.Button(button_frame, text="Decrypt", command=self.decrypt_message)
        self.decrypt_btn.pack(side=tk.LEFT, padx=(0, 10))
        
        self.clear_btn = ttk.Button(button_frame, text="Clear All", command=self.clear_all)
        self.clear_btn.pack(side=tk.LEFT)
        
        # Result output
        ttk.Label(main_frame, text="Result:").grid(row=4, column=0, sticky=tk.W, pady=(0, 5))
        self.result_text = scrolledtext.ScrolledText(main_frame, height=6, width=50)
        self.result_text.grid(row=5, column=0, columnspan=2, sticky=(tk.W, tk.E))
        
        # Set fixed key for encryption/decryption
        self.fixed_key = 'python'
        
        # Set default message (from original code)
        self.message_text.insert('1.0', '')
    
    def encrypt_message(self):
        message = self.message_text.get('1.0', tk.END).strip()
        
        if not message:
            self.result_text.delete('1.0', tk.END)
            self.result_text.insert('1.0', "Please enter a message to encrypt.")
            return
        
        try:
            encrypted = encrypt(message, self.fixed_key)
            self.result_text.delete('1.0', tk.END)
            self.result_text.insert('1.0', encrypted)
        except Exception as e:
            self.result_text.delete('1.0', tk.END)
            self.result_text.insert('1.0', f"Error: {str(e)}")
    
    def decrypt_message(self):
        message = self.message_text.get('1.0', tk.END).strip()
        
        if not message:
            self.result_text.delete('1.0', tk.END)
            self.result_text.insert('1.0', "Please enter a message to decrypt.")
            return
        
        try:
            decrypted = decrypt(message, self.fixed_key)
            self.result_text.delete('1.0', tk.END)
            self.result_text.insert('1.0', decrypted)
        except Exception as e:
            self.result_text.delete('1.0', tk.END)
            self.result_text.insert('1.0', f"Error: {str(e)}")
    
    def clear_all(self):
        self.message_text.delete('1.0', tk.END)
        self.result_text.delete('1.0', tk.END)

if __name__ == "__main__":
    root = tk.Tk()
    app = TextCryptGUI(root)
    root.mainloop()