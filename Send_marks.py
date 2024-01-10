# import tkinter as tk
# from tkinter import messagebox
# import sqlite3
# import gnupg
# from datetime import datetime
# import os
# import socket
# import json
# def generate_key_pair(gpg, key_type, key_length, name, email, passphrase):
#     key_params = {
#         'Key-Type': key_type,
#         'Key-Length': key_length,
#         'Name-Real': name,
#         'Name-Email': email,
#         'Passphrase': passphrase,
#     }

#     input_data = gpg.gen_key_input(**key_params)
#     key = gpg.gen_key(input_data)
    
#     return key

# def export_keys(gpg, fingerprint, passphrase=None):
#     public_key = gpg.export_keys(fingerprint)
#     private_key = gpg.export_keys(fingerprint, secret=True, passphrase=passphrase)
    
#     return public_key, private_key

# def import_public_key(gpg, key_data):
#     return gpg.import_keys(key_data)

# def sign_data(gpg, private_key_fingerprint, data):
#     signature = gpg.sign(data, keyid=private_key_fingerprint, detach=True)
#     return signature

# def verify_signature(gpg, public_key, data, signature):
#     verification_result = gpg.verify_data(signature, data, keyring=public_key)
#     return verification_result.valid
# def encrypt_message(gpg, recipient_key, message):
#     try:
#         # Import the recipient's public key
#         import_result = gpg.import_keys(recipient_key)
#         if not import_result.results or not import_result.results[0]['fingerprint']:
#             print("Invalid recipient key.")
#             return None

#         recipient_fingerprint = import_result.results[0]['fingerprint']

#         # Encrypt the message using the recipient's key
#         encrypted_data = gpg.encrypt(message, recipient_fingerprint)
        
#         if encrypted_data.ok:
#             return str(encrypted_data)
#         else:
#             print("Encryption failed. Details:", encrypted_data.status)
#             return None

#     except Exception as e:
#         print("Error during encryption:", str(e))
#         return None

# def decrypt_message(gpg, message):
#     decrypted_data = gpg.decrypt(message)
#     return str(decrypted_data)

# def create_user_if_not_exists(conn, username, type):
#     # بحث عن المستخدم باستخدام اسم المستخدم ونوعه
#     query = f"SELECT * FROM userdata WHERE username = ? AND type = ?"
#     cursor = conn.execute(query, (username, type))
#     existing_user = cursor.fetchone()
   
#     if not existing_user:
#         messagebox.showerror("Error", "There is no account with this name. Please create an account")
        
#         return False
#     else:
#         return True
# conn = sqlite3.connect("userdata.db")
# cur = conn.cursor()
# def generate_or_load_key(gpg, name, email, passphrase):
#     # تحقق من وجود مفتاح باستخدام اسم المستخدم
#         existing_keys = gpg.list_keys(keys=[name])
        
#         if existing_keys: 
#             print(f"Found existing key for {name}.")
#             fingerprint = existing_keys[0]['fingerprint']
#             public_key, private_key = export_keys(gpg, fingerprint, passphrase=passphrase)
#         else:
#             print(f"No existing key found for {name}. Generating a new key.")
#             client_key = generate_key_pair(gpg, 'RSA', 1024, name, email, passphrase)
#             fingerprint = client_key.fingerprint
#             public_key, private_key = export_keys(gpg, fingerprint, passphrase=passphrase)
        
#         return public_key, private_key ,  fingerprint  

#         ##############################################
       
    
# def get_current_date(self):
#     return datetime.now().strftime("%Y-%m-%d %H:%M:%S") 

# def save_grade():
# # username = self.username_entry.get()
# # type = self.type_entry.get()
# # passphrase=self.password_entry.get()
# # subject = self.subject_entry.get()
# # mark = self.mark_entry.get()
# # date = self.date_entry.get()
# # print(username)
# # print(type)
# # print(subject)
# # print(mark)
# # print(date)
#     username = input("Enter your name: ")
#     type = input("Enter type: ")
#     passphrase = input("Enter passphrase: ")
#     path = r"C:\Program Files (x86)\GPG\GPG\GnuPG\bin\gpg.exe"
#     home = r"C:\Users\Amera\Pictures\server\gpg"
#     os.environ["GNUPGHOME"] = home
#     gpg = gnupg.GPG(gnupghome=home)

#     email = f"{username}@gmail.com" 
#     exist= create_user_if_not_exists(conn,username,type)
#     if exist:
#         client_key, _ ,finger = generate_or_load_key(gpg, username, email, passphrase)
      
#         # client_key, _, finger = generate_or_load_key(gpg, conn, cur, student_name,type, password)
#         print("Client Key Loaded:")
#         client_public_key, private = export_keys(gpg, finger, passphrase='server_passphrase')
#         print("--------------1-------------")
#         print("basic Public Key:")
#         print(client_public_key)
#         print("private Key:")
#         print(private)
#         # تكوين المأخذ
#         client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#         client_socket.connect(('127.0.0.1', 8888))  # اختر نفس رقم المنفذ الذي اخترته للسيرفر
#         client_socket.sendall("mark".encode())
#         # var= client_socket.recv(1024).decode('utf-8')
#         # إرسال المفتاح العام للسيرفر
#         server_public_key = client_socket.recv(1024).decode('utf-8')
#         client_socket.sendall(client_public_key.encode('utf-8'))

#         # استقبال المفتاح العام من السيرفر
        
#         print("--------------2-------------")
#         print("Received Server Public Key:")
#         print(server_public_key)
#         student_data = {'John': 100, 'ola': 200, 'ali': 150}
    
#     # تحويل القائمة إلى سلسلة نصية
#         data_string = json.dumps(student_data)
#         signature= sign_data(gpg, finger,data_string )
#         print("Signature:")
#         print(signature)
#         client_socket.sendall(data_string.encode('utf-8'))
#         client_socket.sendall(signature.data)
# save_grade()
      
#         # التحقق من أن جميع الحقول تملأ
#         # if not username or not user_type or not subject or not grade or not date:
#         #     tk.messagebox.showwarning("خطأ", "الرجاء ملء جميع الحقول.")
#         #     return

#         # # التحقق من وجود المستخدم
#         # self.cur.execute('SELECT id FROM userdata WHERE username = ? AND type = ?', (username, user_type))
#         # user_id = self.cur.fetchone()

#         # # إذا كان المستخدم غير موجود، قم بإنشاءه واحصل على id
#         # if not user_id:
#         #     tk.messagebox.showerror("Error", "There is no account with this name. Please create an account")
#         # else:
#         #     user_id = user_id[0]

#         # # إدراج العلامة في جدول العلامات مع id المستخدم
#         # self.cur.execute('INSERT INTO grades (user_id, subject, grade, date) VALUES (?, ?, ?, ?)',
#         #                  (user_id, subject, grade, date))
#         # self.conn.commit()
#         # tk.messagebox.showinfo("نجاح", "تم حفظ العلامة بنجاح.")

# # root = tk.Tk()
# # app = GradeApp(root)
# # root.mainloop()

import gnupg
import tkinter as tk
import socket
import os
import sqlite3
import pickle
import hashlib
import json
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from tkinter import messagebox
from datetime import datetime



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

def create_user_if_not_exists(conn, username, type):
    # بحث عن المستخدم باستخدام اسم المستخدم ونوعه
    query = f"SELECT * FROM userdata WHERE username = ? AND type = ?"
    cursor = conn.execute(query, (username, type))
    existing_user = cursor.fetchone()
   
    if not existing_user:
        messagebox.showerror("Error", "There is no account with this name. Please create an account")
        
        return False
    else:
        return True
def export_keys(gpg, fingerprint, passphrase=None):
    public_key = gpg.export_keys(fingerprint)
    private_key = gpg.export_keys(fingerprint, secret=True, passphrase=passphrase)
    
    return public_key, private_key

def import_public_key(gpg, key_data):
    return gpg.import_keys(key_data)


conn = sqlite3.connect("userdata.db")
cur = conn.cursor()


def is_doctor(username):
    # افتح اتصالاً بقاعدة البيانات
    connection = sqlite3.connect('userdata.db')
    cursor = connection.cursor()

    try:
        # استعلام للبحث عن المستخدم بناءً على الاسم والنوع
        query = "SELECT id FROM userdata WHERE username = ? AND type = 'doctor'"
        cursor.execute(query, (username,))
        user_id = cursor.fetchone()

        if user_id:
            # المستخدم هو دكتور
            return True
        else:
            # المستخدم ليس دكتور
            messagebox.showerror("Error", "Sorry, you are not a doctor and you do not have the authority to perform this operation")
            return False

    except Exception as e:
        print("ERROR:", str(e))
        return False

    finally:
        # أغلق الاتصال بقاعدة البيانات
        connection.close()

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

def sign_message(private_key, message):
    signature = private_key.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature

# def create_signed_message(gpg, finger, doctor_name, subject_name, marks):
#     # Create the message using user input
#     message = f"Doctor: {doctor_name}\nSubject: {subject_name}\nMarks: {marks}"
    
# # Sign the message using the private key identified by the fingerprint
#     signature = gpg.sign(message, keyid=finger, clearsign=True)

#     return message, signature.data.decode('utf-8')

def create_signed_message(gpg, finger, doctor_name, subject_name, marks):
    # Create the message using user input
    # message = f"Doctor: {doctor_name}\nSubject: {subject_name}\nMarks: {marks}"
    message1 = {
            "doctor_name": doctor_name,
            "subject_name": subject_name,
            "marks": marks
            }
    message = json.dumps(message1)
# Sign the message using the private key identified by the fingerprint
    signature = gpg.sign(message, keyid=finger, clearsign=True)

    return message1, signature.data.decode('utf-8')

class GradeApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Send Marks")
       
        # إنشاء جدول العلامات إذا لم يكن موجودًا
        self.label = tk.Label(root, text="Enter your Marks:", font=("Helvetica", 16))
        self.label.grid(row=0, column=0, columnspan=2, pady=10)

        self.username_label = tk.Label(root, text="Doctor_name:")
        self.username_label.grid(row=1, column=0, pady=5, padx=10, sticky="e")

        self.username_entry = tk.Entry(root, width=30)
        self.username_entry.grid(row=1, column=1, pady=5, padx=10)
        
       
        
        self.password_label = tk.Label(root, text="Pasphrase:")
        self.password_label.grid(row=3, column=0, pady=5, padx=10, sticky="e")

        self.password_entry = tk.Entry(root, width=30)
        self.password_entry.grid(row=3, column=1, pady=5, padx=10)

        self.subject_label = tk.Label(root, text="Subject:")
        self.subject_label.grid(row=4, column=0, pady=5, padx=10, sticky="e")

        self.subject_entry = tk.Entry(root, width=30)
        self.subject_entry.grid(row=4, column=1, pady=5, padx=10)

        self.mark_label = tk.Label(root, text="Marks_list:")
        self.mark_label.grid(row=5, column=0, pady=5, padx=10, sticky="e")

        self.mark_entry = tk.Entry(root, width=30)
        self.mark_entry.grid(row=5, column=1, pady=5, padx=10)

        self.date_label = tk.Label(root, text="Date:")
        
        self.date_label.grid(row=6, column=0, pady=5, padx=10, sticky="e")

        self.date_entry = tk.Entry(root, width=30)
        self.date_entry.insert(0, self.get_current_date())
        self.date_entry.grid(row=6, column=1, pady=5, padx=10)

        self.create_button = tk.Button(root, text="Send Mark", command=self.save_grade)
        self.create_button.grid(row=7, column=1,  pady=10, padx=40)
# تكوين مفتاح GPG
        
    def get_current_date(self):
      return datetime.now().strftime("%Y-%m-%d %H:%M:%S") 
    
    def save_grade(self):
        Docter_name= self.username_entry.get()
    
        passphrase=self.password_entry.get()
        subject_name = self.subject_entry.get()
        Marks = self.mark_entry.get()
        date = self.date_entry.get()
        path = r"C:\Program Files (x86)\gnupg\bin\gpg.exe"
        home = r"D:\server\gpg"
        os.environ["GNUPGHOME"] = home
        gpg = gnupg.GPG(gnupghome=home)
        print("--------------1-------------")
        # Docter_name  = input("Enter Docter name:")
        # subject_name = input("Enter the subject: ")
        # Marks = input("Enter the MArks: ")
       
        email = f"{Docter_name}@example.com"  # يمكنك تغيير البريد الإلكتروني حسب الحاجة
        # passphrase = input("Enter your passphrase: ")
        # ادخال معلومات المستخدم
        isdoctor = is_doctor( Docter_name )
        if isdoctor:
                print("okkkkk")
                client_key, private_key, finger =  generate_or_load_key(gpg, Docter_name, email, passphrase)

                print("okkkkk")
                with open("ip_address.txt", 'r') as file:
                  ip= file.read()

                with open("port.txt", 'r') as file:
                    port  = file.read()
                port1=int(port)
                # تكوين المأخذ
                client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                client_socket.connect((ip, port1))  # اختر نفس رقم المنفذ الذي اخترته للسيرفر
                print("okkkkk")
                client_public_key, private_key = export_keys(gpg, finger, passphrase='server_passphrase')
                print("okkkkk")
                client_socket.sendall("mark".encode())
                print("okkkkk")
                # إرسال المفتاح العام للسيرفر
                client_socket.sendall(client_public_key.encode('utf-8'))
                print("okkkkk")
                # استقبال المفتاح العام من السيرفر
                server_public_key = client_socket.recv(1024).decode('utf-8')
                print("---------2----------")
                message, signature = create_signed_message(gpg, finger, Docter_name, subject_name, Marks)
                print(signature)
                print("--------------send signtures to server -------------")
                encrypted_message = encrypt_message(gpg, server_public_key,signature)
                if encrypted_message is not None:
                    print("signtures after encrypt:", encrypted_message)

                # Send the encrypted message
                client_socket.sendall(encrypted_message.encode('utf-8'))
                print("-------------send mesaage to the server ------------")
                # # message = {
                # #     "doctor_name": doctor_name,
                # #     "subject_name": subject_name,
                # #     "marks": marks
                # #     }
                doctor_name = message["doctor_name"]
                subject_name = message["subject_name"]
                marks = message["marks"]
                encrypted_doctor_name = encrypt_message(gpg,server_public_key, doctor_name)
                encrypted_subject_name = encrypt_message(gpg,server_public_key, subject_name)
                encrypted_marks  = encrypt_message(gpg,server_public_key, marks )
                encrypted_message= {
                    "doctor_name": encrypted_doctor_name ,
                    "subject_name": encrypted_subject_name,
                    "marks": encrypted_marks
                    }
                message = json.dumps(encrypted_message)
                # encrypted_message = encrypt_message(gpg, server_public_key,message)
                client_socket.send(pickle.dumps(encrypted_message))
                # client_socket.sendall(message.encode('utf-8'))
                # client_socket.sendall(encrypted_message.encode('utf-8'))
                # if encrypted_message is not None:
                #     print("message after encrypt:", encrypted_message)
                received_id = client_socket.recv(4096)  # قد تحتاج لزيادة هذا الرقم حسب حجم البيانات
                received_value = pickle.loads(received_id)
                print(f"{ received_value} received_value")
                messagebox.showinfo("signature and verify", f"The signed marks list has been received, the signature has been successfully verified, and this is the unique ID for the list : { received_value}")

                client_socket.close()
    
root = tk.Tk()
app = GradeApp(root)
root.mainloop()