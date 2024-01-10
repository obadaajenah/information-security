import tkinter as tk
from tkinter import messagebox
import sqlite3
from Crypto import Random
import pickle
import base64
import socket
from Crypto.Cipher import AES
import subprocess

def Encrypt(msg, key):
    padding = "*"
    block_size = 16
    iv = Random.new().read(16)
    q = lambda a: a + (block_size - len(a) % block_size) * padding
    E = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = base64.b64encode(iv + E.encrypt(q(msg).encode('ascii')))
    data = [key, ciphertext]
    return data

def create_user_if_not_exists( username, type):
    conn = sqlite3.connect("userdata.db")
    cur = conn.cursor()
    # بحث عن المستخدم باستخدام اسم المستخدم ونوعه
    query = f"SELECT * FROM userdata WHERE username = ? AND type = ?"
    cursor = conn.execute(query, (username, type))
    existing_user = cursor.fetchone()
   
    if not existing_user:
        messagebox.showerror("Error", "There is no account with this name. Please create an account")
        return False
    else:
        return True


class SendInfoApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Send Info")

        self.label = tk.Label(root, text="Enter your information:", font=("Helvetica", 16))
        self.label.grid(row=0, column=0, columnspan=2, pady=10)

        self.username_label = tk.Label(root, text="Username:")
        self.username_label.grid(row=1, column=0, pady=5, padx=10, sticky="e")

        self.username_entry = tk.Entry(root, width=30)
        self.username_entry.grid(row=1, column=1, pady=5, padx=10)
        
        self.type_label = tk.Label(root, text="Type:")
        self.type_label.grid(row=2, column=0, pady=5, padx=10, sticky="e")

        self.type_entry = tk.Entry(root, width=30)
        self.type_entry.grid(row=2, column=1, pady=5, padx=10)

        self.phone_label = tk.Label(root, text="ID_number:")
        self.phone_label.grid(row=3, column=0, pady=5, padx=10, sticky="e")

        self.phone_entry = tk.Entry(root, width=30)
        self.phone_entry.grid(row=3, column=1, pady=5, padx=10)

        self.mobile_label = tk.Label(root, text="Mobile Number:")
        self.mobile_label.grid(row=4, column=0, pady=5, padx=10, sticky="e")

        self.mobile_entry = tk.Entry(root, width=30)
        self.mobile_entry.grid(row=4, column=1, pady=5, padx=10)

        self.address_label = tk.Label(root, text="Address:")
        self.address_label.grid(row=5, column=0, pady=5, padx=10, sticky="e")

        self.address_entry = tk.Entry(root, width=30)
        self.address_entry.grid(row=5, column=1, pady=5, padx=10)

        self.create_button = tk.Button(root, text="Send Info", command=self.complete_account)
        self.create_button.grid(row=6, column=1,  pady=10, padx=40)
        
        self.create_button_create = tk.Button(root, text="create account", command=self.creat_acc)
        self.create_button_create.grid(row=6, column=2, pady=10, padx=10)


    def creat_acc(self):
        subprocess.run(['python', 'account.py'])

    def complete_account(self):
        
        username = self.username_entry.get()
        type = self.type_entry.get()
        ID_number = self.phone_entry.get()
        mobile_number = self.mobile_entry.get()
        address = self.address_entry.get()

        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        
    # إنشاء مأخذ (socket)
    # الاتصال بالخادم
        with open("ip_address.txt", 'r') as file:
                ip= file.read()

        with open("port.txt", 'r') as file:
            port  = file.read()
        port1=int(port)   
        server_address = (ip, port1)
        client_socket.connect(server_address)
        
        if len(ID_number) % 16 !=0:
            ID_numb= ID_number+ ' ' * (16 - len(ID_number) % 16)
            with open("encrypted_id_number.txt", 'w') as file:
                file.write(ID_numb)
        else:
            with open("encrypted_id_number.txt", 'w') as file:
                file.write(ID_number)
        try:
            with open("encrypted_id_number.txt", 'r') as file:
                shared_key = file.read()
            
        except FileNotFoundError:
            print("Encrypted ID Number file not found.")  
                
        a = Encrypt(username ,shared_key.encode('ascii'))
        b = Encrypt(mobile_number ,shared_key.encode('ascii'))
        c = Encrypt(address ,shared_key.encode('ascii'))
        d = Encrypt(ID_number ,shared_key.encode('ascii'))
        e = Encrypt(type ,shared_key.encode('ascii'))
        data = {
        "encrypted_username": a,
        "encrypted_mobile_number": b,
        "encrypted_address": c,
        "encrypted_ID_number": d,
        "encrypted_type": e
        }
        encrypted_username = a[1]
        encrypted_mobile_number = b[1]
        encrypted_address = c[1]
        encrypted_ID_number= d[1]
        encrypted_type= e[1]

        print("key is:" ,shared_key.encode('ascii'))
        print( "username",encrypted_username)
        print( "mobile",encrypted_mobile_number)
        print( "address",encrypted_address)
        print( "idnumber",encrypted_ID_number)
        print( "type",encrypted_type)
        client_socket.sendall("info".encode())
        client_socket.send(pickle.dumps(data))
    
        # tk.messagebox.showinfo("Send Info", "Information sent successfully!")
        self.root.destroy()  # إغلاق النافذة بعد إرسال المعلومات
        

      
        
    
    
# Create an instance of the Tkinter window
root = tk.Tk()

# Create an instance of the CreateAccountApp
app = SendInfoApp(root)

# Run the Tkinter main loop
root.mainloop()
