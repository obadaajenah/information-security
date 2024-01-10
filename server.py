# import socket
# import traceback
# from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
# import gnupg
# import socket
# import os
# import base64
# from Crypto.Cipher import AES
# import hashlib
# import sqlite3
# import threading
# import pickle
# from datetime import datetime
# import json
# import random
# import subprocess
# from cryptography.hazmat.primitives import serialization, hashes
# from cryptography.hazmat.primitives.asymmetric import rsa
# from OpenSSL import crypto
# from cryptography import x509
# from cryptography.hazmat.primitives import hashes
# from cryptography.x509.oid import NameOID
# from cryptography.x509 import Name, NameAttribute
# from cryptography.hazmat.backends import default_backend
# from datetime import datetime, timedelta ,timezone
# from cryptography.hazmat.primitives.asymmetric import padding
# from cryptography.x509 import load_pem_x509_certificate
# from tkinter import messagebox
# import ssl
# import tkinter as tk

# def Decrypt( ciphertext ,key):
#     iv = base64.b64decode(ciphertext)[:16]
#     encrypted_message = base64.b64decode(ciphertext)[16:]
#     D = AES.new(key, AES.MODE_CBC, iv)
#     plaintext = D.decrypt(encrypted_message).decode('ascii')
#     return plaintext.rstrip("*")
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
# def create_projects_table():
#     try:
#         # Create a connection and cursor
#         conn = sqlite3.connect("userdata.db")
#         cur = conn.cursor()

#         # Execute SQL to create the table
#         cur.execute('''
#             CREATE TABLE IF NOT EXISTS projects (
#                 id INTEGER PRIMARY KEY,
#                 student_id INTEGER REFERENCES userdata(id),
#                 name TEXT NOT NULL,
#                 description TEXT,
                
#                 FOREIGN KEY (student_id) REFERENCES  userdata(id)
#             );
#         ''')

#         # Commit the changes
#         conn.commit()

#     finally:
#         # Close the cursor and connection in a finally block to ensure they are closed
#         cur.close()
#         conn.close()   

# def generate_or_load_key(gpg, name, email, passphrase):
#     # تحقق من وجود مفتاح باستخدام اسم المستخدم
#     existing_keys = gpg.list_keys(keys=[name])
    
#     if existing_keys:
#         print(f"Found existing key for {name}.")
#         fingerprint = existing_keys[0]['fingerprint']
#         public_key, private_key = export_keys(gpg, fingerprint, passphrase=passphrase)
#     else:
#         print(f"No existing key found for {name}. Generating a new key.")
#         client_key = generate_key_pair(gpg, 'RSA', 1024, name, email, passphrase)
#         fingerprint = client_key.fingerprint
#         public_key, private_key = export_keys(gpg, fingerprint, passphrase=passphrase)
    
#     return public_key, private_key ,  fingerprint

# def generate_equation():
#     num1 = random.randint(1, 10)
#     num2 = random.randint(1, 10)
#     num3 = random.randint(1, 10)
#     num4 = random.randint(1, 10)
#     operator1 = random.choice(['+', '-', '*'])
#     operator2 = random.choice(['+', '-', '*'])
#     operator3 = random.choice(['+', '-', '*'])
#     equation = f"{num1} {operator1}  {num4} {operator3} {num2} {operator2} {num3}"
#     return equation    
# # def sign_data(gpg, private_key_fingerprint, data):
# #     signature = gpg.sign(data, keyid=private_key_fingerprint, detach=True)
# #     return signature


# # def verify_signature(gpg, public_key, data, signature):
# #     verification_result = gpg.verify_data(signature, data, key_data=public_key)
# #     return verification_result.valid

# def insert_project( student_id,user  ,name, description):
#     conn = sqlite3.connect("userdata.db")
#     cur = conn.cursor()
    
#     cur.execute('''
#         INSERT INTO projects (student_id,name, description)
#         VALUES (?, ?, ?)
#     ''', (student_id,name, description))
#     conn.commit()    

# def encrypt(message, key):
#     cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
#     encryptor = cipher.encryptor()

#     # تحويل النص إلى بايتات باستخدام ترميز utf-8
#     message_bytes = message.encode('utf-8')

#     # جعل طول البيانات مضاعفًا لطول كتلة البيانات (block length)
#     block_size = 16
#     padded_message = message_bytes + b'\0' * (block_size - len(message_bytes) % block_size)

#     ct = encryptor.update(padded_message) + encryptor.finalize()
#     return ct

# def decrypt(ciphertext, key):
#     cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
#     decryptor = cipher.decryptor()

#     pt = decryptor.update(ciphertext) + decryptor.finalize()

#     # تحويل النص إلى Unicode بعد فك التشفير
#     decrypted_message = pt.decode('utf-8')
#     return decrypted_message
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

# def extract_certificate_type(cert):
#     for extension in cert.extensions:
#         if isinstance(extension.value, x509.SubjectAlternativeName):
#             for name in extension.value:
#                 if isinstance(name, x509.DNSName):
#                     return name.value  # لا داعي لاستخدام decode هنا

#     return None
# def create_Marks_table():
#     try:
#         # Create a connection and cursor
#         conn = sqlite3.connect("userdata.db")
#         cur = conn.cursor()
        
        
#         # Execute SQL to create the table
#         cur.execute('''
#             CREATE TABLE IF NOT EXISTS marks (
#                 id INTEGER PRIMARY KEY,
#                 Docter_name VARCHAR(50) NOT NULL,
#                 subject  VARCHAR(50) NOT NULL,   
#                 marks TEXT NOT NULL,
#                 ID_generation  INTEGER NOT NULL,   
#                 timestamp DATETIME
#             );
#         ''')

#         # Commit the changes
#         conn.commit()

#     finally:
#         # Close the cursor and connection in a finally block to ensure they are closed
#         cur.close()
#         conn.close()   

# def insert_marks( Docter_name,marks,subject,ID_generation):
#     conn = sqlite3.connect("userdata.db")
#     cur = conn.cursor()
    
#     # Get the current timestamp
#     timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
   

#     try:
#         cur.execute('''
#         INSERT INTO marks (Docter_name,marks,subject,ID_generation,timestamp)
#         VALUES (?, ?, ?,?,?)
#     ''', (Docter_name,marks,subject,ID_generation,timestamp ))
#         conn.commit()

#     except sqlite3.Error as e:
#         print("error", e)

#     finally:
#         # إغلاق الاتصال في أي حالة
#         conn.close()

# def verify_signature(gpg, message, signature, public_key):
#     # Import the public key for verification
#     gpg.import_keys(public_key)

#     # Verify the signature
#     verified = gpg.verify(signature)

#     # Check if the verification was successful
#     if verified:
#         print("Signature verification successful.")
#         print("Verified by:", verified.username)
#         print("Signature creation time:", verified.sig_timestamp)
#         return True, verified.username, verified.sig_timestamp
#     else:
#         print("Signature verification failed.")
#         return False, None, None
# def login(s,c , client_id):
    
#     c.send("Username: ".encode()) 
#     username = c.recv(1024).decode() 
    
#     c.send("Type: ".encode()) 
#     type= c.recv(1024).decode() 

#     c.send("Password: ".encode()) 
#     password = c.recv(1024).decode() 
#     # host_name = s.gethostname()
#     # # احصل على عنوان IP للجهاز
#     # ip_address = s.gethostbyname(host_name)
#     # # اعيد العنوان ورقم البورت
#     # msg ="Server IP: 127.0.0.1 , Port: 8888"
#     # print(msg)
#     hashed_password = hashlib.sha256(password.encode()).hexdigest() 
    
#     conn = sqlite3.connect("userdata.db")
#     cur = conn.cursor()

#     cur.execute("SELECT * FROM userdata WHERE username = ?  AND password = ? AND type = ? " , (username , hashed_password ,type))
#     if cur.fetchall():
#         print("database")
#         c.send(" Login successful!".encode())
#         name_type=f"{username}_{type}"
#         if type =="doctor":
#             if os.path.exists(os.path.join("CSR",f"{name_type}_sign_sert.pem")):
#                print(f"الشهادة  موجودة في المجلد.")
#             else:
#                 equation = generate_equation()
#                 print("Generated Equation:", equation)
#                 # equation = "2 * (3 + 15) + 10 -2 "  # يمكنك تعديل المعادلة حسب احتياجاتك
#                 c.sendall(equation.encode())
#                 equation_result = eval(equation)
#                 answer = hashlib.sha256(str(equation_result).encode()).hexdigest()
#                 # الخطوة 3: استلام الإجابة من العميل
#                 received_answer = c.recv(4096).decode()
#                 print("correct",answer)
#                 print("answer",received_answer)

#                 if received_answer== answer:
#                         print("correct.....") 
#                         subprocess.run(['python', 'CSR.py'])

        
        
#     else:
#         c.send(" Login faild".encode()) 
#         print("nooo")



# def create_user_if_not_exists( username, type):
#     conn = sqlite3.connect("userdata.db")
#     cur = conn.cursor()
#     # بحث عن المستخدم باستخدام اسم المستخدم ونوعه
#     query = f"SELECT * FROM userdata WHERE username = ? AND type = ?"
#     cursor = conn.execute(query, (username, type))
#     existing_user = cursor.fetchone()
   
#     if not existing_user:
#         messagebox.showerror("Error", "There is no account with this name. Please create an account")
#         return False
#     else:
#         return True 
# def get_user_id(self, username,type_user):
#         conn = sqlite3.connect("userdata.db")
#         cur = conn.cursor()
#         cur.execute("SELECT id FROM userdata WHERE username = ? AND type = ?", (username,type_user))
#         user_id = cur.fetchone()
#         print("id user1 ",  user_id)
#                 # إذا كان الطالب موجوداً، يتم حفظ معلومات المشروع
#         if user_id:
#                     user_id = user_id[0]
#                     print("id user 2",  user_id)
#                     return user_id
#         else: 
#              return None
        

# def account_exists( ID_number):
#         conn = sqlite3.connect("userdata.db")
#         cur = conn.cursor()
        
#         cur.execute("""
# CREATE TABLE IF NOT EXISTS userdetails (
#     id INTEGER PRIMARY KEY,
#     user_id INTEGER REFERENCES userdata(id),
#     ID_number VARCHAR(15) NOT NULL,
#     mobile_number VARCHAR(15) NOT NULL,
#     address VARCHAR(255) NOT NULL,
#     FOREIGN KEY (user_id) REFERENCES userdata(id)
# );             
# """)
        
#         cur.execute("SELECT * FROM userdetails WHERE ID_number=?", (ID_number,))
#         result = cur.fetchone()
#         conn.commit()
#         cur.close()
#         conn.close()
#         return result is not None



# def create_user_if_not_exists( username, type):
#     conn = sqlite3.connect("userdata.db")
#     cur = conn.cursor()
#     # بحث عن المستخدم باستخدام اسم المستخدم ونوعه
#     query = f"SELECT * FROM userdata WHERE username = ? AND type = ?"
#     cursor = conn.execute(query, (username, type))
#     existing_user = cursor.fetchone()
   
#     if not existing_user:
#         messagebox.showerror("Error", "There is no account with this name. Please create an account")
#         return False
#     else:
#         return True
    
# def complete_account(username,type,ID_number):

#     exist= create_user_if_not_exists(username,type)
#     if exist:
#         user_id = get_user_id(username,type)    
#         print("id user3 ",  user_id)
#         if user_id is None:
#             tk.messagebox.showerror("Error", "There is no account with this name. Please create an account")
#             return

#         if account_exists(ID_number):
#             tk.messagebox.showerror("Error", "ID_number already exists. Choose a different ID_number.")
#             return
    
        

# def get_user_id( username,type_user):
#     conn = sqlite3.connect("userdata.db")
#     cur = conn.cursor()
#     cur.execute("SELECT id FROM userdata WHERE username = ? AND type = ?", (username,type_user))
#     user_id = cur.fetchone()
#     print("id user1 ",  user_id)
#             # إذا كان الطالب موجوداً، يتم حفظ معلومات المشروع
#     if user_id:
#                 user_id = user_id[0]
#                 print("id user 2",  user_id)
#                 return user_id
#     else: 
#             return None
# def send_info(client_socket, client_id):
#     try:
      
#         try:
#             with open("encrypted_id_number.txt", 'r') as file:
#               shared_key = file.read()
              
               
#         except FileNotFoundError:
#             print("Encrypted ID Number file not found.")  
        
#         data = client_socket.recv(4096)
#         recv = pickle.loads(data)
#         encrypted_username = recv["encrypted_username"]
#         encrypted_mobile_number = recv["encrypted_mobile_number"]
#         encrypted_address = recv["encrypted_address"]
#         encrypted_ID_number = recv["encrypted_ID_number"]
#         encrypted_type = recv["encrypted_type"]
#         print("befor encrption", encrypted_username)
#         print("befor encrption:",  encrypted_mobile_number )
#         print("befor encrption", encrypted_address)
#         print("befor encrption:",  encrypted_ID_number)
#         print("befor encrption:",  encrypted_type)
#         decrypted_message1 = Decrypt( encrypted_username[1] ,  shared_key.encode('ascii'))
#         decrypted_message2 = Decrypt( encrypted_mobile_number[1],  shared_key.encode('ascii'))
#         decrypted_message3 = Decrypt( encrypted_address[1], shared_key.encode('ascii'))
#         decrypted_message4 = Decrypt(  encrypted_ID_number[1], shared_key.encode('ascii'))
#         decrypted_message5 = Decrypt( encrypted_type[1], shared_key.encode('ascii'))
#         print("after :", decrypted_message1)
#         print("after:", decrypted_message2)
#         print("after:", decrypted_message3)
#         print("after:", decrypted_message4)
#         print("after:", decrypted_message5)
        
#         # get_user_id( decrypted_message1,decrypted_message5)
        
#         exist= create_user_if_not_exists(decrypted_message1,decrypted_message5)
#         if exist:
#             user_id = get_user_id(decrypted_message1,decrypted_message5)    
#             print("id user3 ",  user_id)
#             if user_id is None:
#                 tk.messagebox.showerror("Error", "There is no account with this name. Please create an account")
#                 return

#             if account_exists(decrypted_message4):
#                 tk.messagebox.showerror("Error", "ID_number already exists. Choose a different ID_number.")
#                 return
            
#             try:


#                 conn = sqlite3.connect("userdata.db")
#                 cur = conn.cursor()
                
#                 cur.execute("INSERT INTO userdetails (user_id, ID_number, mobile_number, address) VALUES (?, ?, ?, ?)",
#                             (user_id, decrypted_message4, decrypted_message2, decrypted_message3))
#                 conn.commit()
#                 tk.messagebox.showinfo("Send Info", "Information sent successfully!")
#             except sqlite3.Error as e:
#               tk.messagebox.showinfo("Error", f"Information sent:{e}")
         
#         # conn = sqlite3.connect("userdata.db")
#         # cur = conn.cursor()

#         # # إدراج البيانات المشفرة في قاعدة البيانات
#         # print("id user 5",  decrypted_message1)
#         # cur.execute("INSERT INTO userdetails (user_id, ID_number, mobile_number, address) VALUES (?, ?, ?, ?)",
#         #             (decrypted_message1, encrypted_username, encrypted_mobile_number, encrypted_address))
#         # conn.commit()

            
                

                

#         # استمرار مع المزيد من المعالجة أو إرسال رد للعميل
#     except Exception as e:
#        traceback.print_exc()  # سيطبع التتبع الكامل للخطأأ




#     # استمرار مع المزيد من المعالجة أو إرسال رد للعميل
# def send_project(c , client_id):
    
#         path = r"C:\Program Files (x86)\GPG\GPG\GnuPG\bin\gpg.exe"
#         home = r"C:\Users\Amera\Pictures\server\gpg"
#         os.environ["GNUPGHOME"] = home

#         # Specify the GPG binary path
#         gpg = gnupg.GPG(gnupghome=home, gpgbinary=path)

     
#         print("Waiting for connection...")
        
#         server_key = generate_key_pair(gpg, 'RSA', 1024, 'Server', 'server@example.com', 'server_passphrase')
#         print("Server Key Generated:")

#         # Export public key for server
#         server_public_key, _ = export_keys(gpg, server_key.fingerprint, passphrase='server_passphrase')
#         print("--------------1-------------")
#         print("basic Public Key:")
#         print(server_public_key)
#         # إرسال المفتاح العام للعميل
#         client_socket.sendall(server_public_key.encode('utf-8'))

#         # استقبال المفتاح العام من العميل
#         client_public_key = client_socket.recv(1024).decode('utf-8')
#         print("--------------2-------------")
#         print("Received Client Public Key:")
#         print(client_public_key)

#         # Receive and decrypt a message from the client
#         received_encrypted_message = client_socket.recv(1024).decode('utf-8')
#         print("--------------3-------------")
#         print("session_key befor decrypt ", received_encrypted_message )

#         decrypted_message = decrypt_message(gpg, received_encrypted_message)
#         print("--------------4-------------")
#         print("Received and Decrypted Message from client:", decrypted_message.encode('latin1'))
#         session_key=decrypted_message.encode('latin1')

#         print("--------------5-------------")

#         message_to_client = "The session key was successfully received"
#         print("Original Message:", message_to_client)
#         encrypted_message = encrypt_message(gpg, server_public_key,message_to_client )
#         if encrypted_message is not None:
#             print("--------------6-------------")
#             print("Encrypted Message:", encrypted_message)

#         # Send the encrypted message
#         client_socket.sendall(encrypted_message.encode('utf-8'))
#         ######


#         # Create projects table if not exists
#         create_projects_table()

#         received_encrypted_AES1 = client_socket.recv(1024)
#         received_encrypted_AES2 = client_socket.recv(1024)
#         name = client_socket.recv(1024).decode()
#         type = client_socket.recv(1024).decode()

#         print("--------------7-------------")

#         print("Received Ciphertext 1:", received_encrypted_AES1)
#         print("Received Ciphertext 2:", received_encrypted_AES2)
#         print("Received Ciphertext 3:", name)
#         print("Received Ciphertext 3:", type)


#         decrypted_message_AES1 = decrypt(received_encrypted_AES1, session_key)
#         decrypted_message_AES2 = decrypt(received_encrypted_AES2, session_key)
#         # decrypted_message_AES3 = decrypt(received_encrypted_AES3, session_key)
#         conn = sqlite3.connect("userdata.db")
#         cur = conn.cursor()
#         cur.execute('SELECT id FROM userdata WHERE username = ? AND type = ?', (name,type))
#         student_id = cur.fetchone()

#                 # إذا كان الطالب موجوداً، يتم حفظ معلومات المشروع
#         if student_id:
#                     student_id = student_id[0]
#         print("id",student_id)
#         conn.commit
#         insert_project( student_id, name,decrypted_message_AES1, decrypted_message_AES2)
#         print("--------------8-------------")
#         print("Decrypted Message:", decrypted_message_AES1)
#         print("--------------8-------------")
#         print("Decrypted Message1:", decrypted_message_AES2)
#         success="Your projects have been successfully received"
#         ciphertext = encrypt(success, session_key) 
#         print("ciphertext",ciphertext)
#         client_socket.send(ciphertext)

# def send_marks(c , client_id):
    
#     path = r"C:\Program Files (x86)\GPG\GPG\GnuPG\bin\gpg.exe"
#     home = r"C:\Users\Amera\Pictures\server\gpg"
#     os.environ["GNUPGHOME"] = home

#     # Specify the GPG binary path
#     gpg = gnupg.GPG(gnupghome=home, gpgbinary=path)

#     # تكوين المأخذ
#     # server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#     # server_socket.bind(('localhost', 12345))  # اختر رقم المنفذ الذي تريده
#     # server_socket.listen(1)
#     # conn = sqlite3.connect("userdata.db")
#     # cur = conn.cursor()

#     #         # Execute SQL to drop the table if it exists
#     # cur.execute('DROP TABLE IF EXISTS marks')

#     #         # Commit the changes
#     # conn.commit()
#     # print("Waiting for connection...")
#     # client_socket, client_address = server_socket.accept()
#     # print("Connection established with", client_address)

#     server_key = generate_key_pair(gpg, 'RSA', 1024, 'Server', 'server@example.com', 'server_passphrase')


#     # Export public key for server
#     server_public_key, _ = export_keys(gpg, server_key.fingerprint, passphrase='server_passphrase')
#     print("--------------1-------------")

#     # إرسال المفتاح العام للعميل
#     client_socket.sendall(server_public_key.encode('utf-8'))

#     # استقبال المفتاح العام من العميل
#     client_public_key = client_socket.recv(1024).decode('utf-8')

#     # create_Marks_table()

#     print("--------------1-------------")
#     received_encrypted_signature = client_socket.recv(1024)

#     print(received_encrypted_signature)
#     signature = decrypt_message(gpg,received_encrypted_signature)
#     print("--------------2------------")
#     print("Received and Decrypted Message from client:",signature)
#     print("----------------------------------------------")
    
#     data = client_socket.recv(4096)
#     recv = pickle.loads(data)
#     encrypted_doctor_name = recv["doctor_name"]
#     encrypted_subject_name = recv["subject_name"]
#     encrypted_marks = recv["marks"]
#     doctor_name = decrypt_message(gpg,encrypted_doctor_name )
#     subject_name = decrypt_message(gpg,encrypted_subject_name )
#     marks = decrypt_message(gpg,encrypted_marks)
#     message1 = {
#                 "doctor_name": doctor_name,
#                 "subject_name": subject_name,
#                 "marks": marks
#                 }
#     message = json.dumps(message1)
#     verification_result, verified_by, creation_id = verify_signature(gpg, message, signature,client_public_key)
#     print("-------------------------------------------------------------------------------")
#     print("doctor name :",message1["doctor_name"])
#     print("subject_name :",message1["subject_name"])
#     print("marks :",message1["marks"])

#     create_Marks_table()
#     insert_marks(message1["doctor_name"],message1["marks"],message1["subject_name"],creation_id)
#     client_socket.send(pickle.dumps(creation_id))
    

# def create_csr(c , client_id):
#     private = rsa.generate_private_key(
#     public_exponent=65537,
#     key_size=2048,
#     backend=default_backend()
# )

# # حفظ المفتاح العام والخاص
#     pem = private.private_bytes(
#         encoding=serialization.Encoding.PEM,
#         format=serialization.PrivateFormat.TraditionalOpenSSL,
#         encryption_algorithm=serialization.NoEncryption()
#     )

#     with open(os.path.join("keys","private_key_server.pem"), "wb") as f:
#         f.write(pem)

#     public_key = private.public_key()
#     pem = public_key.public_bytes(
#         encoding=serialization.Encoding.PEM,
#         format=serialization.PublicFormat.SubjectPublicKeyInfo
#     )

#     with open(os.path.join("keys","public_key_server.pem"), "wb") as f:
#         f.write(pem)

#     with open(os.path.join("keys","private_key_server.pem"), "rb") as key_file:
#         private_key = serialization.load_pem_private_key(
#             key_file.read(),
#             password=None,
#             backend=default_backend()
#         )



#     client_socket.sendall("a".encode())
#     name_client = client_socket.recv(1024).decode()
#     print("name", name_client)
#     client_socket.sendall(pem)
#     # استقبال ملف CSR من العميل
#     print("public key ",pem)
#     received_csr = client_socket.recv(4096)
#     print(received_csr )
#     client_socket.sendall("a".encode())
#     signature = client_socket.recv(4096)
#     print("signature",signature)
#     with open(os.path.join("keys",f"{name_client}_public_key.pem"), 'rb') as ca_public_key_file:
#         ca_public_key_data = ca_public_key_file.read()
#         public_key_client = serialization.load_pem_public_key(ca_public_key_data, backend=default_backend())
#         print("verify .............")
#     try:
#         public_key_client.verify(signature,received_csr , padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
#         print("yessss")
#         csr = x509.load_pem_x509_csr(received_csr, default_backend())
#         certificate_type_extracted = extract_certificate_type(csr)

#         # طباعة نوع الشهادة (يمكنك استخدامها كمرجع في السيرفر)
#         print("Type certificate ", certificate_type_extracted)
        
      
#         subject = csr.subject
#         signed_cert = x509.CertificateBuilder().subject_name(
#                 subject
#             ).issuer_name(
#                 subject
#             ).public_key(
#                 csr.public_key()
#             ).serial_number(
#                 x509.random_serial_number()
#             ).not_valid_before(
#                 datetime.now(timezone.utc)  # تحديد وقت البداية
#             ).not_valid_after(
#                 datetime.now(timezone.utc) + timedelta(days=3650)  # تاريخ انتهاء صالح لمدة 10 سنوات
#             ).add_extension(
#                 x509.BasicConstraints(ca=False, path_length=None), critical=True
#             ).sign(private_key, hashes.SHA256(), default_backend())
            
#         with open("signed_cert.pem", "wb") as f:
#             f.write(signed_cert.public_bytes(serialization.Encoding.PEM))
#         with open("signed_cert.pem", "rb") as cert_file:
#             cert_data = cert_file.read()
#         print(cert_data)
#         client_socket.sendall(cert_data )
            
#     except Exception as e:
#             print("noooooooo")
#             print(f"خطأ في التحقق: {e}")

#     # server_socket.close()
# with open("ip_address.txt", 'r') as file:
#        ip= file.read()

# with open("port.txt", 'r') as file:
#      port  = file.read()
# port1=int(port)
# server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
# server_address = (ip, port1)
# server_socket.bind(server_address)
# server_socket.listen()
# # conn = sqlite3.connect("userdata.db")
# # cur = conn.cursor()

# #         # Execute SQL to drop the table if it exists
# # cur.execute('DROP TABLE IF EXISTS userdata')

# #         # Commit the changes
# # conn.commit()
# print('Waiting for a connection...')

# client_id = 1

# try:
#     while True:
#         client_socket, client_address = server_socket.accept()
#         print(f"Accepted connection from {client_address}")
        
#         request_type = client_socket.recv(1024).decode()
        
#         print(request_type )
#         if request_type == "login":
#             threading.Thread(target=login, args=(server_socket,client_socket, client_id)).start()
#         # elif request_type == "signup":
#         #     threading.Thread(target=handle_signup, args=(client_socket, client_id)).start()
#         elif request_type == "info":
#             threading.Thread(target=send_info, args=(client_socket, client_id)).start()
#         elif request_type == "project":
#             threading.Thread(target=send_project, args=(client_socket, client_id)).start()
#         elif request_type == "mark":
#             threading.Thread(target=send_marks, args=(client_socket, client_id)).start()
#         elif request_type == "csr":
#             threading.Thread(target=create_csr, args=(client_socket, client_id)).start()
        
#         client_id += 1
        
        
# except Exception as e:
#         traceback.print_exc()
# finally:
#         server_socket.close()

####################################################################################


import socket
import traceback
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import gnupg
import socket
import os
import base64
from Crypto.Cipher import AES
import hashlib
import sqlite3
import threading
import pickle
from datetime import datetime
import json
import random
import subprocess
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from OpenSSL import crypto
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import NameOID
from cryptography.x509 import Name, NameAttribute
from cryptography.hazmat.backends import default_backend
from datetime import datetime, timedelta ,timezone
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.x509 import load_pem_x509_certificate
import tkinter as tk
from tkinter import messagebox
import ssl


def Decrypt( ciphertext ,key):
    iv = base64.b64decode(ciphertext)[:16]
    encrypted_message = base64.b64decode(ciphertext)[16:]
    D = AES.new(key, AES.MODE_CBC, iv)
    plaintext = D.decrypt(encrypted_message).decode('ascii')
    return plaintext.rstrip("*")
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

def export_keys(gpg, fingerprint, passphrase=None):
    public_key = gpg.export_keys(fingerprint)
    private_key = gpg.export_keys(fingerprint, secret=True, passphrase=passphrase)
    
    return public_key, private_key

def import_public_key(gpg, key_data):
    return gpg.import_keys(key_data)
def create_projects_table():
    try:
        # Create a connection and cursor
        conn = sqlite3.connect("userdata.db")
        cur = conn.cursor()

        # Execute SQL to create the table
        cur.execute('''
            CREATE TABLE IF NOT EXISTS projects (
                id INTEGER PRIMARY KEY,
                student_id INTEGER REFERENCES userdata(id),
                name TEXT NOT NULL,
                description TEXT,
                
                FOREIGN KEY (student_id) REFERENCES  userdata(id)
            );
        ''')

        # Commit the changes
        conn.commit()

    finally:
        # Close the cursor and connection in a finally block to ensure they are closed
        cur.close()
        conn.close()   

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

def generate_equation():
    num1 = random.randint(1, 10)
    num2 = random.randint(1, 10)
    num3 = random.randint(1, 10)
    num4 = random.randint(1, 10)
    operator1 = random.choice(['+', '-', '*'])
    operator2 = random.choice(['+', '-', '*'])
    operator3 = random.choice(['+', '-', '*'])
    equation = f"{num1} {operator1}  {num4} {operator3} {num2} {operator2} {num3}"
    return equation    
# def sign_data(gpg, private_key_fingerprint, data):
#     signature = gpg.sign(data, keyid=private_key_fingerprint, detach=True)
#     return signature


# def verify_signature(gpg, public_key, data, signature):
#     verification_result = gpg.verify_data(signature, data, key_data=public_key)
#     return verification_result.valid
def insert_project( student_id,user  ,name, description):
    conn = sqlite3.connect("userdata.db")
    cur = conn.cursor()
    
    cur.execute('''
        INSERT INTO projects (student_id,name, description)
        VALUES (?, ?, ?)
    ''', (student_id,name, description))
    conn.commit()    

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

def extract_certificate_type(cert):
    for extension in cert.extensions:
        if isinstance(extension.value, x509.SubjectAlternativeName):
            for name in extension.value:
                if isinstance(name, x509.DNSName):
                    return name.value  # لا داعي لاستخدام decode هنا

    return None
def create_Marks_table():
    try:
        # Create a connection and cursor
        conn = sqlite3.connect("userdata.db")
        cur = conn.cursor()
        
        
        # Execute SQL to create the table
        cur.execute('''
            CREATE TABLE IF NOT EXISTS marks (
                id INTEGER PRIMARY KEY,
                Docter_name VARCHAR(50) NOT NULL,
                subject  VARCHAR(50) NOT NULL,   
                marks TEXT NOT NULL,
                ID_generation  INTEGER NOT NULL,   
                timestamp DATETIME
            );
        ''')

        # Commit the changes
        conn.commit()

    finally:
        # Close the cursor and connection in a finally block to ensure they are closed
        cur.close()
        conn.close()   

def insert_marks( Docter_name,marks,subject,ID_generation):
    conn = sqlite3.connect("userdata.db")
    cur = conn.cursor()
    
    # Get the current timestamp
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
   

    try:
        cur.execute('''
        INSERT INTO marks (Docter_name,marks,subject,ID_generation,timestamp)
        VALUES (?, ?, ?,?,?)
    ''', (Docter_name,marks,subject,ID_generation,timestamp ))
        conn.commit()

    except sqlite3.Error as e:
        print("error", e)

    finally:
        # إغلاق الاتصال في أي حالة
        conn.close()

def verify_signature(gpg, message, signature, public_key):
    # Import the public key for verification
    gpg.import_keys(public_key)

    # Verify the signature
    verified = gpg.verify(signature)




# Check if the verification was successful
    if verified:
        print("Signature verification successful.")
        print("Verified by:", verified.username)
        print("Signature creation time:", verified.sig_timestamp)
        return True, verified.username, verified.sig_timestamp
    else:
        print("Signature verification failed.")
        return False, None, None
    
def account_exists( username,type):
        print("name",username)
        print("type",type)
        conn = sqlite3.connect("userdata.db")
        cur = conn.cursor()
        cur.execute("""
CREATE TABLE IF NOT EXISTS userdata(
    id INTEGER PRIMARY KEY,
    username VARCHAR(255) NOT NULL,
    password VARCHAR(255) NOT NULL,
    type VARCHAR(255) NOT NULL        
)             
""")
        cur.execute("SELECT * FROM userdata WHERE username=? AND type=?", (username, type))
        result = cur.fetchone()
        conn.close()
        return result is not None

def login(s,c , client_id):
    
    c.send("Username: ".encode()) 
    username = c.recv(1024).decode() 
    
    c.send("Type: ".encode()) 
    type= c.recv(1024).decode() 

    c.send("Password: ".encode()) 
    password = c.recv(1024).decode() 
    # host_name = s.gethostname()
    # # احصل على عنوان IP للجهاز
    # ip_address = s.gethostbyname(host_name)
    # # اعيد العنوان ورقم البورت
    # msg ="Server IP: 127.0.0.1 , Port: 8888"
    # print(msg)
    hashed_password = hashlib.sha256(password.encode()).hexdigest() 
    
    conn = sqlite3.connect("userdata.db")
    cur = conn.cursor()

    cur.execute("SELECT * FROM userdata WHERE username = ?  AND password = ? AND type = ? " , (username , hashed_password ,type))
    if cur.fetchall():
        print("database")
        c.send(" Login successful!".encode())
        name_type=f"{username}_{type}"
        if type =="doctor":
            if os.path.exists(os.path.join("CSR",f"{name_type}_sign_sert.pem")):
               print(f"الشهادة  موجودة في المجلد.")
            else:
                equation = generate_equation()
                print("Generated Equation:", equation)
                # equation = "2 * (3 + 15) + 10 -2 "  # يمكنك تعديل المعادلة حسب احتياجاتك
                c.sendall(equation.encode())
                equation_result = eval(equation)
                answer = hashlib.sha256(str(equation_result).encode()).hexdigest()
                # الخطوة 3: استلام الإجابة من العميل
                received_answer = c.recv(4096).decode()
                print("correct",answer)
                print("answer",received_answer)

                if received_answer== answer:
                        print("correct.....") 
                        subprocess.run(['python', 'CSR.py'])

        
        
    else:
        c.send(" Login faild".encode()) 
        print("nooo")


def account(c, client_id): 
    
    c.send("Username: ".encode()) 
    username = c.recv(1024).decode() 
    print( "name",username )
    c.send("Type: ".encode()) 
    type= c.recv(1024).decode() 
    print( "type",type )
    c.send("Password: ".encode()) 
    password = c.recv(1024).decode() 
    print( "pass",password )
    hashed_password = hashlib.sha256(password.encode()).hexdigest() 
   
   
    if account_exists(username,type):
           
            tk.messagebox.showerror("Error", "Username already exists. Choose a different username.")
            return
    else:
        try:
            conn = sqlite3.connect("userdata.db")
            cur = conn.cursor()
        
            cur.execute("INSERT INTO userdata (username, password,type) VALUES (?, ?,?)", (username, hashed_password,type))
            conn.commit()
          
            tk.messagebox.showinfo("Account Created", "Account created successfully!")
      
        except sqlite3.Error as e:
          
            tk.messagebox.showerror("Error", f"Error creating account: {e}")




            conn.close()






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
def get_user_id(self, username,type_user):
        conn = sqlite3.connect("userdata.db")
        cur = conn.cursor()
        cur.execute("SELECT id FROM userdata WHERE username = ? AND type = ?", (username,type_user))
        user_id = cur.fetchone()
        print("id user1 ",  user_id)
                # إذا كان الطالب موجوداً، يتم حفظ معلومات المشروع
        if user_id:
                    user_id = user_id[0]
                    print("id user 2",  user_id)
                    return user_id
        else: 
             return None
        

def account_exists1( ID_number):
        conn = sqlite3.connect("userdata.db")
        cur = conn.cursor()
        
        cur.execute("""
CREATE TABLE IF NOT EXISTS userdetails (
    id INTEGER PRIMARY KEY,
    user_id INTEGER REFERENCES userdata(id),
    ID_number VARCHAR(15) NOT NULL,
    mobile_number VARCHAR(15) NOT NULL,
    address VARCHAR(255) NOT NULL,
    FOREIGN KEY (user_id) REFERENCES userdata(id)
);             
""")
        
        cur.execute("SELECT * FROM userdetails WHERE ID_number=?", (ID_number,))
        result = cur.fetchone()
        conn.commit()
        cur.close()
        conn.close()
        return result is not None



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
    
def complete_account(username,type,ID_number):

    exist= create_user_if_not_exists(username,type)
    if exist:
        user_id = get_user_id(username,type)    
        print("id user3 ",  user_id)
        if user_id is None:
            tk.messagebox.showerror("Error", "There is no account with this name. Please create an account")
            return

        if account_exists1(ID_number):
            tk.messagebox.showerror("Error", "ID_number already exists. Choose a different ID_number.")
            return
    
        

def get_user_id( username,type_user):
    conn = sqlite3.connect("userdata.db")
    cur = conn.cursor()
    cur.execute("SELECT id FROM userdata WHERE username = ? AND type = ?", (username,type_user))
    user_id = cur.fetchone()
    print("id user1 ",  user_id)
            # إذا كان الطالب موجوداً، يتم حفظ معلومات المشروع
    if user_id:
                user_id = user_id[0]
                print("id user 2",  user_id)
                return user_id
    else: 
            return None
def send_info(client_socket, client_id):
    try:
      
        try:
            with open("encrypted_id_number.txt", 'r') as file:
              shared_key = file.read()
              
               
        except FileNotFoundError:
            print("Encrypted ID Number file not found.")  
        
        data = client_socket.recv(4096)
        recv = pickle.loads(data)
        encrypted_username = recv["encrypted_username"]
        encrypted_mobile_number = recv["encrypted_mobile_number"]
        encrypted_address = recv["encrypted_address"]
        encrypted_ID_number = recv["encrypted_ID_number"]
        encrypted_type = recv["encrypted_type"]
        print("befor encrption", encrypted_username)
        print("befor encrption:",  encrypted_mobile_number )
        print("befor encrption", encrypted_address)
        print("befor encrption:",  encrypted_ID_number)
        print("befor encrption:",  encrypted_type)
        decrypted_message1 = Decrypt( encrypted_username[1] ,  shared_key.encode('ascii'))
        decrypted_message2 = Decrypt( encrypted_mobile_number[1],  shared_key.encode('ascii'))
        decrypted_message3 = Decrypt( encrypted_address[1], shared_key.encode('ascii'))
        decrypted_message4 = Decrypt(  encrypted_ID_number[1], shared_key.encode('ascii'))
        decrypted_message5 = Decrypt( encrypted_type[1], shared_key.encode('ascii'))
        print("after :", decrypted_message1)
        print("after:", decrypted_message2)
        print("after:", decrypted_message3)
        print("after:", decrypted_message4)
        print("after:", decrypted_message5)
        
        # get_user_id( decrypted_message1,decrypted_message5)
        
        # exist= create_user_if_not_exists(decrypted_message1,decrypted_message5)
        # if exist:
        #     user_id = get_user_id(decrypted_message1,decrypted_message5)    
        #     print("id user3 ",  user_id)
        #     if user_id is None:
        #         tk.messagebox.showerror("Error", "There is no account with this name. Please create an account")
        #         return

        #     if account_exists(decrypted_message4):
        #         tk.messagebox.showerror("Error", "ID_number already exists. Choose a different ID_number.")
        #         return
            
        #     try:
                

        #         conn = sqlite3.connect("userdata.db")
        #         cur = conn.cursor()
                
        #         cur.execute("INSERT INTO userdetails (user_id, ID_number, mobile_number, address) VALUES (?, ?, ?, ?)",
        #                     (user_id, decrypted_message4, decrypted_message2, decrypted_message3))
        #         conn.commit()
        #         tk.messagebox.showinfo("Send Info", "Information sent successfully!")
        #     except sqlite3.Error as e:
        #       tk.messagebox.showinfo("Error", f"Information sent:{e}")
        exist = create_user_if_not_exists(decrypted_message1, decrypted_message5)

        if exist:
            user_id = get_user_id(decrypted_message1, decrypted_message5)
            print("id user3 ", user_id)
            
            if user_id is None:
                tk.messagebox.showerror("Error", "There is no account with this name. Please create an account")
                return

            if account_exists1(decrypted_message4):
                tk.messagebox.showerror("Error", "ID_number already exists. Choose a different ID_number.")
                return

            try:
                conn = sqlite3.connect("userdata.db")
                cur = conn.cursor()

                # Check if the user_id already exists in userdetails table
                cur.execute("SELECT * FROM userdetails WHERE user_id = ?", (user_id,))
                existing_user_id = cur.fetchone()

                if existing_user_id:
                    tk.messagebox.showerror("Error", "User ID already exists in userdetails table.")
                    return

                # Insert the data if user_id doesn't exist in userdetails table
                cur.execute("INSERT INTO userdetails (user_id, ID_number, mobile_number, address) VALUES (?, ?, ?, ?)",
                            (user_id, decrypted_message4, decrypted_message2, decrypted_message3))
                conn.commit()
                tk.messagebox.showinfo("Send Info", "Information sent successfully!")

            except sqlite3.Error as e:
                tk.messagebox.showinfo("Error", f"Information sent:{e}") 
            # conn = sqlite3.connect("userdata.db")
            # cur = conn.cursor()

            # # إدراج البيانات المشفرة في قاعدة البيانات
            # print("id user 5",  decrypted_message1)
            # cur.execute("INSERT INTO userdetails (user_id, ID_number, mobile_number, address) VALUES (?, ?, ?, ?)",
            #             (decrypted_message1, encrypted_username, encrypted_mobile_number, encrypted_address))
            # conn.commit()

            
                

                

        # استمرار مع المزيد من المعالجة أو إرسال رد للعميل
    except Exception as e:
         traceback.print_exc()  # سيطبع التتبع الكامل للخطأأ

def send_project(c , client_id):
    
        path = r"C:\Program Files (x86)\gnupg\bin\gpg.exe"
        home = r"D:\server\gpg"
        os.environ["GNUPGHOME"] = home

        # Specify the GPG binary path
        gpg = gnupg.GPG(gnupghome=home, gpgbinary=path)

     
        print("Waiting for connection...")
        
        server_key = generate_key_pair(gpg, 'RSA', 1024, 'Server', 'server@example.com', 'server_passphrase')
        print("Server Key Generated:")

        # Export public key for server
        server_public_key, _ = export_keys(gpg, server_key.fingerprint, passphrase='server_passphrase')
        print("--------------1-------------")
        print("basic Public Key:")
        print(server_public_key)
        # إرسال المفتاح العام للعميل
        client_socket.sendall(server_public_key.encode('utf-8'))

        # استقبال المفتاح العام من العميل
        client_public_key = client_socket.recv(1024).decode('utf-8')
        print("--------------2-------------")
        print("Received Client Public Key:")
        print(client_public_key)

        # Receive and decrypt a message from the client
        received_encrypted_message = client_socket.recv(1024).decode('utf-8')
        print("--------------3-------------")
        print("session_key befor decrypt ", received_encrypted_message )

        decrypted_message = decrypt_message(gpg, received_encrypted_message)
        print("--------------4-------------")
        print("Received and Decrypted Message from client:", decrypted_message.encode('latin1'))
        session_key=decrypted_message.encode('latin1')

        print("--------------5-------------")

        message_to_client = "The session key was successfully received"
        print("Original Message:", message_to_client)
        encrypted_message = encrypt_message(gpg, server_public_key,message_to_client )
        if encrypted_message is not None:
            print("--------------6-------------")
            print("Encrypted Message:", encrypted_message)

        # Send the encrypted message
        client_socket.sendall(encrypted_message.encode('utf-8'))
        ######


        # Create projects table if not exists
        create_projects_table()

        received_encrypted_AES1 = client_socket.recv(1024)
        received_encrypted_AES2 = client_socket.recv(1024)
        name = client_socket.recv(1024).decode()
        type = client_socket.recv(1024).decode()



        print("--------------7-------------")

        print("Received Ciphertext 1:", received_encrypted_AES1)
        print("Received Ciphertext 2:", received_encrypted_AES2)
        print("Received Ciphertext 3:", name)
        print("Received Ciphertext 3:", type)


        decrypted_message_AES1 = decrypt(received_encrypted_AES1, session_key)
        decrypted_message_AES2 = decrypt(received_encrypted_AES2, session_key)
        # decrypted_message_AES3 = decrypt(received_encrypted_AES3, session_key)
        conn = sqlite3.connect("userdata.db")
        cur = conn.cursor()
        cur.execute('SELECT id FROM userdata WHERE username = ? AND type = ?', (name,type))
        student_id = cur.fetchone()

                # إذا كان الطالب موجوداً، يتم حفظ معلومات المشروع
        if student_id:
                    student_id = student_id[0]
        print("id",student_id)
        conn.commit
        insert_project( student_id, name,decrypted_message_AES1, decrypted_message_AES2)
        print("--------------8-------------")
        print("Decrypted Message:", decrypted_message_AES1)
        print("--------------8-------------")
        print("Decrypted Message1:", decrypted_message_AES2)
        success="Your projects have been successfully received"
        ciphertext = encrypt(success, session_key) 
        print("ciphertext",ciphertext)
        client_socket.send(ciphertext)

def send_marks(c , client_id):
    
    path = path = r"C:\Program Files (x86)\gnupg\bin\gpg.exe"
    home = r"D:\server\gpg"
    os.environ["GNUPGHOME"] = home

    # Specify the GPG binary path
    gpg = gnupg.GPG(gnupghome=home, gpgbinary=path)

    # تكوين المأخذ
    # server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # server_socket.bind(('localhost', 12345))  # اختر رقم المنفذ الذي تريده
    # server_socket.listen(1)
    # conn = sqlite3.connect("userdata.db")
    # cur = conn.cursor()

    #         # Execute SQL to drop the table if it exists
    # cur.execute('DROP TABLE IF EXISTS marks')

    #         # Commit the changes
    # conn.commit()
    # print("Waiting for connection...")
    # client_socket, client_address = server_socket.accept()
    # print("Connection established with", client_address)

    server_key = generate_key_pair(gpg, 'RSA', 1024, 'Server', 'server@example.com', 'server_passphrase')


    # Export public key for server
    server_public_key, _ = export_keys(gpg, server_key.fingerprint, passphrase='server_passphrase')
    print("--------------1-------------")

    # إرسال المفتاح العام للعميل
    client_socket.sendall(server_public_key.encode('utf-8'))

    # استقبال المفتاح العام من العميل
    client_public_key = client_socket.recv(1024).decode('utf-8')

    # create_Marks_table()

    print("--------------1-------------")
    received_encrypted_signature = client_socket.recv(1024)

    print(received_encrypted_signature)
    signature = decrypt_message(gpg,received_encrypted_signature)
    print("--------------2------------")
    print("Received and Decrypted Message from client:",signature)
    print("----------------------------------------------")
    
    data = client_socket.recv(4096)
    recv = pickle.loads(data)
    encrypted_doctor_name = recv["doctor_name"]
    encrypted_subject_name = recv["subject_name"]
    encrypted_marks = recv["marks"]
    doctor_name = decrypt_message(gpg,encrypted_doctor_name )
    subject_name = decrypt_message(gpg,encrypted_subject_name )
    marks = decrypt_message(gpg,encrypted_marks)
    message1 = {
                "doctor_name": doctor_name,
                "subject_name": subject_name,
                "marks": marks
                }
    message = json.dumps(message1)
    verification_result, verified_by, creation_id = verify_signature(gpg, message, signature,client_public_key)
    print("-------------------------------------------------------------------------------")
    print("doctor name :",message1["doctor_name"])
    print("subject_name :",message1["subject_name"])
    print("marks :",message1["marks"])       
    create_Marks_table()
    insert_marks(message1["doctor_name"],message1["marks"],message1["subject_name"],creation_id)
    client_socket.send(pickle.dumps(creation_id))
    

def create_csr(c , client_id):
    private = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)

# حفظ المفتاح العام والخاص
    pem = private.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )

    with open(os.path.join("keys","private_key_server.pem"), "wb") as f:
        f.write(pem)

    public_key = private.public_key()
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    with open(os.path.join("keys","public_key_server.pem"), "wb") as f:
        f.write(pem)

    with open(os.path.join("keys","private_key_server.pem"), "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,
            backend=default_backend()
        )



    client_socket.sendall("a".encode())
    name_client = client_socket.recv(1024).decode()
    print("name", name_client)
    client_socket.sendall(pem)
    # استقبال ملف CSR من العميل
    print("public key ",pem)
    received_csr = client_socket.recv(4096)
    print(received_csr )
    client_socket.sendall("a".encode())
    signature = client_socket.recv(4096)
    print("signature",signature)
    with open(os.path.join("keys",f"{name_client}_public_key.pem"), 'rb') as ca_public_key_file:
        ca_public_key_data = ca_public_key_file.read()
        public_key_client = serialization.load_pem_public_key(ca_public_key_data, backend=default_backend())
        print("verify .............")
    try:
        public_key_client.verify(signature,received_csr , padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
        print("yessss")
        csr = x509.load_pem_x509_csr(received_csr, default_backend())
        certificate_type_extracted = extract_certificate_type(csr)

        # طباعة نوع الشهادة (يمكنك استخدامها كمرجع في السيرفر)
        print("Type certificate ", certificate_type_extracted)
        
      
        subject = csr.subject
        signed_cert = x509.CertificateBuilder().subject_name(
                subject
            ).issuer_name(
                subject
            ).public_key(
                csr.public_key()
            ).serial_number(
                x509.random_serial_number()
            ).not_valid_before(
                datetime.now(timezone.utc)  # تحديد وقت البداية
            ).not_valid_after(
                datetime.now(timezone.utc) + timedelta(days=3650)  # تاريخ انتهاء صالح لمدة 10 سنوات
            ).add_extension(
                x509.BasicConstraints(ca=False, path_length=None), critical=True
            ).sign(private_key, hashes.SHA256(), default_backend())
            
        with open("signed_cert.pem", "wb") as f:
            f.write(signed_cert.public_bytes(serialization.Encoding.PEM))
        with open("signed_cert.pem", "rb") as cert_file:
            cert_data = cert_file.read()
        print(cert_data)
        client_socket.sendall(cert_data )
            
    except Exception as e:
            print("noooooooo")
            print(f"خطأ في التحقق: {e}")

    # server_socket.close()
with open("ip_address.txt", 'r') as file:
       ip= file.read()

with open("port.txt", 'r') as file:
     port  = file.read()
port1=int(port)
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_address = (ip, port1)
server_socket.bind(server_address)
server_socket.listen()
# conn = sqlite3.connect("userdata.db")
# cur = conn.cursor()

#         # Execute SQL to drop the table if it exists
# cur.execute('DROP TABLE IF EXISTS userdata')

#         # Commit the changes
# conn.commit()
print('Waiting for a connection...')

client_id = 1
try:
    while True:
        client_socket, client_address = server_socket.accept()
        print(f"Accepted connection from {client_address}")
        
        request_type = client_socket.recv(1024).decode()
        
        print(request_type )
        if request_type == "login":
            threading.Thread(target=login, args=(server_socket,client_socket, client_id)).start()
        elif request_type == "account":
            threading.Thread(target=account, args=(client_socket, client_id)).start()
        elif request_type == "info":
            threading.Thread(target=send_info, args=(client_socket, client_id)).start()
        elif request_type == "project":
            threading.Thread(target=send_project, args=(client_socket, client_id)).start()
        elif request_type == "mark":
            threading.Thread(target=send_marks, args=(client_socket, client_id)).start()
        elif request_type == "csr":
            threading.Thread(target=create_csr, args=(client_socket, client_id)).start()
        
        client_id += 1
        
        
except Exception as e:
        traceback.print_exc()
finally:
        server_socket.close()
