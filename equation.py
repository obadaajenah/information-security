with open("ip_address.txt", 'r') as file:
       ip= file.read()

with open("port.txt", 'r') as file:
     port  = file.read()
print(ip)
print(port)











# import socket
# import traceback
# from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
# from cryptography.hazmat.backends import default_backend
# import gnupg
# import socket
# import os
# import sqlite3
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

# # def execute_on_condition(text):
# #     # يتم تنفيذ هذا الكود عندما يكون الشرط صحيحًا
# #     # print("تم تنفيذ الشرط!")

# #     # إنشاء نافذة tkinter
# #     window = tk.Tk()
# #     window.title(" Solve Equation")
# #     spacer_frame = tk.Frame(window, height=20)
# #     spacer_frame.pack()
# #     # إضافة جملة إلى الواجهة
# #     label = tk.Label(window, text=f" Solve this  Equation: {text}")
# #     # label = tk.Label(window, text=)
# #     label.pack()
# #     spacer_frame = tk.Frame(window, height=20)
# #     spacer_frame.pack()
# #     # حقل إدخال نص
# #     entry = tk.Entry(window)
# #     entry.pack()
# #     spacer_frame = tk.Frame(window, height=20)
# #     spacer_frame.pack()
# #     # زر
# #     button = tk.Button(window, text=" send answer",command=lambda: set_equation(text,entry.get()))
# #     button.pack()
# #     window.geometry("250x200")
# #     window.update_idletasks()
# #     screen_width = window.winfo_screenwidth()
# #     screen_height = window.winfo_screenheight()
# #     x_coordinate = (screen_width - window.winfo_reqwidth()) // 2
# #     y_coordinate = (screen_height - window.winfo_reqheight()) // 2
# #     window.geometry(f"+{x_coordinate}+{y_coordinate}")
    
#     # تشغيل الواجهة
#     # window.mainloop()   

#     # print( "ans"answer)
    
#     # الخطوة 3: استلام الإجابة من العميل
#     # received_answer = c.recv(4096).decode()
#     # print("correct",answer)
#     # print("answer",ans)

#     # if ans== equation_result :
#     #     print("correct.....") 
#         # subprocess.run(['python', 'CSR.py'])
#         # return entry.get()
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
#                 solve=eval(equation)
#                 # ans=""
#                 # execute_on_condition(equation)
#                 window = tk.Tk()
#                 window.title(" Solve Equation")
#                 spacer_frame = tk.Frame(window, height=20)
#                 spacer_frame.pack()
#                 # إضافة جملة إلى الواجهة
#                 label = tk.Label(window, text=f" Solve this  Equation: {equation}")
#                 # label = tk.Label(window, text=)
#                 label.pack()
#                 spacer_frame = tk.Frame(window, height=20)
#                 spacer_frame.pack()
#                 # حقل إدخال نص
#                 entry = tk.Entry(window)
#                 entry.pack()
#                 spacer_frame = tk.Frame(window, height=20)
#                 spacer_frame.pack()
#                 # زر
#                 button = tk.Button(window, text=" send answer",command=  on_button_click # لإغلاق النافذة
# )
#                 button.pack()
#                 spacer_frame = tk.Frame(window, height=20)
#                 spacer_frame.pack()
#                 label_result = tk.Label(window, text="")
#                 label_result.pack()

#                 window.geometry("250x200")
#                 window.update_idletasks()
#                 screen_width = window.winfo_screenwidth()
#                 screen_height = window.winfo_screenheight()
#                 x_coordinate = (screen_width - window.winfo_reqwidth()) // 2
#                 y_coordinate = (screen_height - window.winfo_reqheight()) // 2
#                 window.geometry(f"+{x_coordinate}+{y_coordinate}")
                
#                 # تشغيل الواجهة
#                 window.mainloop()  
#             def on_button_click():
#               ans = entry.get()
#               label_result.config(text=f"your Answer is correct")
#                 # ans=entry.get() 
#                 # if ans ==solve:
#                 #     print("correct....")
#                 # print("Generated Equation:", equation)
#                 # equation = "2 * (3 + 15) + 10 -2 "  # يمكنك تعديل المعادلة حسب احتياجاتك
#                 # c.sendall(equation.encode())
                

        
        
#     else:
#         c.send(" Login faild".encode()) 
#         print("nooo")
    
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
#         print("befor encrption", encrypted_username)
#         print("befor encrption:",  encrypted_mobile_number )
#         print("befor encrption", encrypted_address)
#         print("befor encrption:",  encrypted_ID_number)
#         decrypted_message1 = Decrypt( encrypted_username[1] ,  shared_key.encode('ascii'))
#         decrypted_message2 = Decrypt( encrypted_mobile_number[1],  shared_key.encode('ascii'))
#         decrypted_message3 = Decrypt( encrypted_address[1], shared_key.encode('ascii'))
#         decrypted_message4 = Decrypt(  encrypted_ID_number[1], shared_key.encode('ascii'))
#         print("after :", decrypted_message1)
#         print("after:", decrypted_message2)
#         print("after:", decrypted_message3)
#         print("after:", decrypted_message4)
       



       
#         # استمرار مع المزيد من المعالجة أو إرسال رد للعميل
#     except Exception as e:
#         traceback.print_exc()  # سيطبع التتبع الكامل للخطأأ
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
    


#     # server_socket.close()
# server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
# server_address = ('127.0.0.1', 8888)
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
        
#         client_id += 1
        
        
# except Exception as e:
#         traceback.print_exc()
# finally:
#         server_socket.close()



