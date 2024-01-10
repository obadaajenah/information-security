

import gnupg
import socket
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import tkinter as tk
import sqlite3
import hashlib
import subprocess
from tkinter import messagebox

def generate_key_pair(gpg, key_type, key_length, name, email, passphrase):
    key_params = {
        'Key-Type': key_type,
        'Key-Length': key_length,
        'Name-Real': name,
        'Name-Email': email,
        'Passphrase': passphrase,
    }

    input_data = gpg.gen_key_input(**key_params)
    key = gpg.gen_key(input_data)
    
    return key
conn = sqlite3.connect("userdata.db")
cur = conn.cursor()
def generate_or_load_key(gpg, name, email, passphrase):
    # تحقق من وجود مفتاح باستخدام اسم المستخدم
    existing_keys = gpg.list_keys(keys=[name])
    
    if existing_keys:
        print(f"Found existing key for {name}.")
        fingerprint = existing_keys[0]['fingerprint']
        public_key, private_key = export_keys(gpg, fingerprint, passphrase=passphrase)
    else:
        print(f"No existing key found for {name}. Generating a new key.")
        client_key = generate_key_pair(gpg, 'RSA', 1024, name, email, passphrase)
        fingerprint = client_key.fingerprint
        public_key, private_key = export_keys(gpg, fingerprint, passphrase=passphrase)
    
    return public_key, private_key ,  fingerprint
def create_user_if_not_exists(self,conn, username, type):
    # بحث عن المستخدم باستخدام اسم المستخدم ونوعه
    query = f"SELECT * FROM userdata WHERE username = ? AND type = ?"
    cursor = conn.execute(query, (username, type))
    existing_user = cursor.fetchone()
   
    if not existing_user:
        messagebox.showerror("Error", "There is no account with this name. Please create an account")
        
        return False
    else:
        return True
        # إذا لم يتم العثور على المستخدم، قم بإنشاء حساب جديد وإضافته إلى الجدول
        # query = f"INSERT INTO userdata (username,password, type) VALUES (?,?, ?)"
        # conn.execute(query, (username,password_hash, type))
        # conn.commit()

def export_keys(gpg, fingerprint, passphrase=None):
    public_key = gpg.export_keys(fingerprint)
    private_key = gpg.export_keys(fingerprint, secret=True, passphrase=passphrase)
    
    return public_key, private_key
#####
def import_public_key(gpg, key_data):
    return gpg.import_keys(key_data)
def register_user(conn, cur, name, type, fingerprint):
    cur.execute("INSERT INTO userdata (username,  password, type) VALUES (?, ?, ?)", (name, fingerprint , type))
    conn.commit()
# def generate_or_load_key(gpg, conn, cur, name, type, passphrase):
#     # Check if the user already exists
#     cur.execute("SELECT * FROM userdata WHERE username = ? AND type = ?", (name, type))
#     existing_user = cur.fetchone()

#     if existing_user:
#         print(f"Found existing key for {name} of type {type}.")
#         fingerprint = existing_user[1]  # Use index 1 for the 'password' column
#         public_key, private_key = export_keys(gpg, fingerprint, passphrase=passphrase)

#         # Check if there is a public key for the user
#         if not public_key:
#             print(f"No public key found for {name}. Generating a new key.")
#             client_key = generate_key_pair(gpg, 'RSA', 1024, name, '', passphrase)
#             fingerprint = client_key.fingerprint
#             public_key, private_key = export_keys(gpg, fingerprint, passphrase=passphrase)


# # Register the new user with the generated fingerprint
#             # register_user(conn, cur, name, fingerprint)
#         else:
#             print(f"Public key found for {name}.")
#     else:
#         print(f"No existing key found for {name} of type {type}. Generating a new key.")
#         client_key = generate_key_pair(gpg, 'RSA', 1024, name, '', passphrase)
#         fingerprint = client_key.fingerprint
#         public_key, private_key = export_keys(gpg, fingerprint, passphrase=passphrase)

#         # Register the new user with the generated fingerprint
#         register_user(conn, cur, name, type, fingerprint)

#     return public_key, private_key, fingerprint



def encrypt(message, key):
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    encryptor = cipher.encryptor()

    # تحويل النص إلى بايتات باستخدام ترميز utf-8
    message_bytes = message.encode('utf-8')

    # جعل طول البيانات مضاعفًا لطول كتلة البيانات (block length)
    block_size = 16
    padded_message = message_bytes + b'\0' * (block_size - len(message_bytes) % block_size)

    ct = encryptor.update(padded_message) + encryptor.finalize()
    return ct

def decrypt(ciphertext, key):
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    decryptor = cipher.decryptor()

    pt = decryptor.update(ciphertext) + decryptor.finalize()

    # تحويل النص إلى Unicode بعد فك التشفير
    decrypted_message = pt.decode('utf-8')
    return decrypted_message
def encrypt_message(gpg, recipient_key, message):
    try:
        # Import the recipient's public key
        import_result = gpg.import_keys(recipient_key)
        if not import_result.results or not import_result.results[0]['fingerprint']:
            print("Invalid recipient key.")
            return None

        recipient_fingerprint = import_result.results[0]['fingerprint']

        # Encrypt the message using the recipient's key
        encrypted_data = gpg.encrypt(message, recipient_fingerprint)
        
        if encrypted_data.ok:
            return str(encrypted_data)
        else:
            print("Encryption failed. Details:", encrypted_data.status)
            return None

    except Exception as e:
        print("Error during encryption:", str(e))
        return None

def decrypt_message(gpg, message):
    decrypted_data = gpg.decrypt(message)
    return str(decrypted_data)
class ProjectApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Student Projects")

        # إنشاء حقول إدخال
        # self.student_name_entry = tk.Entry(root, width=30)
        # self.type_entry = tk.Entry(root, width=30)
        # self.password_entry = tk.Entry(root, width=30)
        # self.project_name_entry = tk.Entry(root, width=30)
        # self.project_description_entry = tk.Entry(root, width=30)

        # إنشاء زر لتخزين المشروع
        # self.save_button = tk.Button(root, text="حفظ", command=self.save_project)
        self.label = tk.Label(root, text="Enter your Projects:", font=("Helvetica", 16))
        self.label.grid(row=0, column=0, columnspan=2, pady=10)

        self.student_name_label = tk.Label(root, text="Student_name:")
        self.student_name_label.grid(row=1, column=0, pady=5, padx=10, sticky="e")

        self.student_name_entry = tk.Entry(root, width=30)
        self.student_name_entry.grid(row=1, column=1, pady=5, padx=10)

        self.type_label = tk.Label(root, text="Type:")
        self.type_label.grid(row=2, column=0, pady=5, padx=10, sticky="e")

        self.type_entry = tk.Entry(root, width=30)
        self.type_entry.grid(row=2, column=1, pady=5, padx=10)

        self.password_label = tk.Label(root, text="Pasphrase:")
        self.password_label.grid(row=3, column=0, pady=5, padx=10, sticky="e")

        self.password_entry = tk.Entry(root, width=30)
        self.password_entry.grid(row=3, column=1, pady=5, padx=10)

        self.project_name_label = tk.Label(root, text="Project_name:")
        self.project_name_label.grid(row=4, column=0, pady=5, padx=10, sticky="e")

        self.project_name_entry = tk.Entry(root, width=30)
        self.project_name_entry.grid(row=4, column=1, pady=5, padx=10)

        self.project_description_label = tk.Label(root, text="Project_description:")
        self.project_description_label.grid(row=5, column=0, pady=5, padx=10, sticky="e")

        self.project_description_entry = tk.Entry(root, width=30)
        self.project_description_entry.grid(row=5, column=1, pady=5, padx=10)
        
        self.create_button_save = tk.Button(root, text="Save project", command=self.save_project)
        self.create_button_save.grid(row=6, column=1, pady=10, padx=40)

        self.create_button_create = tk.Button(root, text="create account", command=self.creat_acc)
        self.create_button_create.grid(row=6, column=2, pady=10, padx=10)


    
    def creat_acc(self):
        subprocess.run(['python', 'account.py'])

# تكوين مفتاح GPG
    def save_project(self):
        student_name = self.student_name_entry.get()
        type = self.type_entry.get()
        password= self.password_entry.get()
        project_name = self.project_name_entry.get()
        project_description = self.project_description_entry.get()
        path = r"C:\Program Files (x86)\gnupg\bin\gpg.exe"
        home = r"D:\server\gpg"
        os.environ["GNUPGHOME"] = home
        gpg = gnupg.GPG(gnupghome=home)

        # ادخال معلومات المستخدم

        # name = input("Enter your name: ")
        # email = student_name + "@gmail.com"
        email=f"{student_name}@gmail.com" 
        print(email) # يمكنك تغيير البريد الإلكتروني حسب الحاجة
        # passphrase = input("Enter your passphrase: ")

        # توليد أو تحميل المفتاح
        exist= create_user_if_not_exists(self,conn,student_name,type)
        if exist:
            client_key, _ ,finger = generate_or_load_key(gpg, student_name, email, password)
            # client_key, _, finger = generate_or_load_key(gpg, conn, cur, student_name,type, password)
            print("Client Key Loaded:")
            client_public_key, _ = export_keys(gpg, finger, passphrase='server_passphrase')
            print("--------------1-------------")
            print("basic Public Key:")
            print(client_public_key)
            # تكوين المأخذ
            client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            with open("ip_address.txt", 'r') as file:
                ip= file.read()

            with open("port.txt", 'r') as file:
                port  = file.read()
            port1=int(port)    
            client_socket.connect((ip, port1))  # اختر نفس رقم المنفذ الذي اخترته للسيرفر
            client_socket.sendall("project".encode())
            # var= client_socket.recv(1024).decode('utf-8')
            # إرسال المفتاح العام للسيرفر
            server_public_key = client_socket.recv(1024).decode('utf-8')
            client_socket.sendall(client_public_key.encode('utf-8'))

            # استقبال المفتاح العام من السيرفر
           
            print("--------------2-------------")
            print("Received Server Public Key:")
            print(server_public_key)



            # Encrypt and send a message to the server

            print("--------------3-------------")

            session_key = os.urandom(32)

            print("session_key befor encrypt ",session_key )
            # Encrypt the message
            print("--------------5-------------")
            print("Using Server Public Key:")

            encrypted_message = encrypt_message(gpg, server_public_key,session_key )
            if encrypted_message is not None:
                print("session_key after encrypt:", encrypted_message)

            # Send the encrypted message
            client_socket.sendall(encrypted_message.encode('utf-8'))

            received_encrypted_message = client_socket.recv(1024).decode('utf-8')
            print("--------------6-------------")
            print("Received decrypted ", received_encrypted_message )
            decrypted_message = decrypt_message(gpg, received_encrypted_message)
            print("Received and Decrypted Message :", decrypted_message)
            ###################################
            # # print("--------------7-------------")
            # # original_message = "Send a list of descriptions of completed practical projects"
            # # print("Original Message:", original_message)
            # # التشفير
            # print("--------------8-------------")
            # ciphertext = encrypt(original_message, session_key)
            # # print("Encrypted Message data:", encrypted_message_AES)
            # # print("Ciphertext:", base64.b64encode(ciphertext).decode())
            # print("Ciphertext:", ciphertext)
            # # client_socket.sendall( encrypted_message_AES)
            # client_socket.sendall( ciphertext)
            # print("--------------8-------------")
            #################################################
            # إغلاق المأخذ
            # project_name = input("Enter the name of the project: ")
            # project_description = input("Enter a description for the project: ")
            print("project Name:", project_name)
            print("project Description:", project_description )
            print("--------------8-------------")
            texts = [project_name,project_description]
            for text in texts:
                ciphertext = encrypt(text, session_key)
                print(f"Original Text: {text}")
                client_socket.sendall(ciphertext)

            client_socket.sendall(student_name.encode())
            client_socket.sendall(type.encode())
            success_recive = client_socket.recv(4096)
            print("success ",success_recive)
            decrypted_success = decrypt(success_recive, session_key)
            print("success after ",decrypted_success )
            tk.messagebox.showinfo("send projects ", f"successfuly: {decrypted_success}"  )
            
            # client_socket.close()
root = tk.Tk()
app = ProjectApp(root)
root.mainloop()