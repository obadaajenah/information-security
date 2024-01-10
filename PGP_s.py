
# import gnupg
# import base64
# import socket
# import os
# import sqlite3
# import time
# from io import BytesIO
# import subprocess
# from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
# from cryptography.hazmat.backends import default_backend
# import os
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

# # تكوين مفتاح GPG
# path = r"C:\Program Files (x86)\GPG\GPG\GnuPG\bin\gpg.exe"
# home = r"C:\Users\Amera\Desktop\server\gpg"
# os.environ["GNUPGHOME"] = home

# # Specify the GPG binary path
# gpg = gnupg.GPG(gnupghome=home, gpgbinary=path)

# # تكوين المأخذ
# server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
# server_socket.bind(('localhost', 12345))  # اختر رقم المنفذ الذي تريده
# server_socket.listen(1)

# print("Waiting for connection...")
# client_socket, client_address = server_socket.accept()
# print("Connection established with", client_address)

# server_key = generate_key_pair(gpg, 'RSA', 1024, 'Server', 'server@example.com', 'server_passphrase')
# print("Server Key Generated:")

# # Export public key for server
# server_public_key, _ = export_keys(gpg, server_key.fingerprint, passphrase='server_passphrase')
# print("--------------1-------------")
# print("basic Public Key:")
# print(server_public_key)
# # إرسال المفتاح العام للعميل
# client_socket.sendall(server_public_key.encode('utf-8'))

# # استقبال المفتاح العام من العميل
# client_public_key = client_socket.recv(1024).decode('utf-8')
# print("--------------2-------------")
# print("Received Client Public Key:")
# print(client_public_key)



# # Receive and decrypt a message from the client
# received_encrypted_message = client_socket.recv(1024).decode('utf-8')
# print("--------------3-------------")
# print("session_key befor decrypt ", received_encrypted_message )
# decrypted_message = decrypt_message(gpg, received_encrypted_message)
# print("--------------4-------------")
# print("session_key after decrypt:", decrypted_message.encode('latin1'))
# session_key=decrypted_message.encode('latin1')
# print("--------------5-------------")
# message_to_client = "The session key was successfully received"
# print("Original Message:", message_to_client)
# encrypted_message = encrypt_message(gpg, server_public_key,message_to_client )
# if encrypted_message is not None:
#     print("--------------6-------------")
#     print("Encrypted Message:", encrypted_message)

# # Send the encrypted message
# client_socket.sendall(encrypted_message.encode('utf-8'))
# # print(session_key)
# # received_encrypted_AES = client_socket.recv(1024)
# # print("--------------7-------------")

# # print("ciphertext:", received_encrypted_AES)
# # decrypted_message_AES = decrypt(received_encrypted_AES, session_key)
# # print("--------------8-------------")
# # print("Decrypted Message:", decrypted_message_AES)
# # print("Decrypted Message:", decrypted_message.decode())
# # إغلاق المأخذ
# create_projects_table()

# received_encrypted_AES1 = client_socket.recv(1024)
# received_encrypted_AES2 = client_socket.recv(1024)
# name = client_socket.recv(1024).decode('utf-8')
# type = client_socket.recv(1024).decode('utf-8')
# print("--------------7-------------")

# print("Received Ciphertext 1:", received_encrypted_AES1)
# print("Received Ciphertext 2:", received_encrypted_AES2)
# print("Received Ciphertext 3:", name)
# print("Received Ciphertext 3:", type)

# decrypted_message_AES1 = decrypt(received_encrypted_AES1, session_key)
# decrypted_message_AES2 = decrypt(received_encrypted_AES2, session_key)
# # decrypted_message_AES3 = decrypt(received_encrypted_AES3, session_key)
# conn = sqlite3.connect("userdata.db")
# cur = conn.cursor()
# cur.execute('SELECT id FROM userdata WHERE username = ? AND type = ?', (name,type))
# student_id = cur.fetchone()

#         # إذا كان الطالب موجوداً، يتم حفظ معلومات المشروع
# if student_id:
#             student_id = student_id[0]
# print("id",student_id)
# conn.commit
# insert_project( student_id, name,decrypted_message_AES1, decrypted_message_AES2)
# print("--------------8-------------")
# print("Decrypted Message:", decrypted_message_AES1)
# print("--------------8-------------")
# print("Decrypted Message1:", decrypted_message_AES2)
# server_socket.close()


from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import gnupg
import socket
import os
import time
from io import BytesIO
import subprocess
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import sqlite3
import socket
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from datetime import datetime
import re
import json


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

def create_Marks_table():
    try:
        # Create a connection and cursor
        conn = sqlite3.connect("userdata.db")
        cur = conn.cursor()
        
        
        # Execute SQL to create the table
        cur.execute('''
            CREATE TABLE IF NOT EXISTS Mark (
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

# def insert_marks( Docter_name,marks,subject,ID_generation):
#     conn = sqlite3.connect("userdata.db")
#     cur = conn.cursor()
    
#     # Get the current timestamp
#     timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
#     cur.execute('''
#         INSERT INTO marks (Docter_name,marks,subject,ID_generation,timestamp)
#         VALUES (?, ?, ?,?,?)
#     ''', (Docter_name,marks,subject,ID_generation,timestamp ))
#     conn.commit()
        



def insert_marks( Docter_name, marks, subject, ID_generation):
    try:
        # Create a connection and cursor
        conn = sqlite3.connect("userdata.db")
        cur = conn.cursor()


# Convert marks dict to a JSON string
        marks_json = json.dumps(marks)
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        # Execute the SQL query with the converted marks
        cur.execute('''
         INSERT INTO marks (Docter_name, marks, subject, ID_generation, timestamp)
         VALUES (?, ?, ?, ?, ?);
        ''', (Docter_name, marks_json, subject, ID_generation, timestamp))

        # Commit the changes
        conn.commit()
        print("Record inserted into the marks table.")

    finally:
        # Close the cursor and connection in a finally block to ensure they are closed
        cur.close()
        conn.close()



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
#         return True
#     else:
#         print("Signature verification failed.")
#         return False

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







path = r"C:\Program Files (x86)\gnupg\bin\gpg.exe"
home = r"D:\Sec-hom\gpg"
os.environ["GNUPGHOME"] = home

# Specify the GPG binary path
gpg = gnupg.GPG(gnupghome=home, gpgbinary=path)

# تكوين المأخذ
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind(('localhost', 12345))  # اختر رقم المنفذ الذي تريده
server_socket.listen(1)

print("Waiting for connection...")
client_socket, client_address = server_socket.accept()
print("Connection established with", client_address)

server_key = generate_key_pair(gpg, 'RSA', 1024, 'Server', 'server@example.com', 'server_passphrase')


# Export public key for server
server_public_key, _ = export_keys(gpg, server_key.fingerprint, passphrase='server_passphrase')
print("--------------1-------------")

# إرسال المفتاح العام للعميل
client_socket.sendall(server_public_key.encode('utf-8'))

# استقبال المفتاح العام من العميل
client_public_key = client_socket.recv(1024).decode('utf-8')

create_Marks_table()

print("--------------1-------------")
received_encrypted_signature = client_socket.recv(1024)

print(received_encrypted_signature)
signature = decrypt_message(gpg,received_encrypted_signature)
print("--------------2------------")
print("Received and Decrypted Message from client:",signature)
print("----------------------------------------------")
received_encrypted_message = client_socket.recv(1024)
print(received_encrypted_message)
message = decrypt_message(gpg,received_encrypted_message)
print("Received and Decrypted Message from client:",message)

# verification_result = verify_signature(gpg, message, signature,client_public_key)
verification_result, verified_by, creation_time = verify_signature(gpg, message, signature,client_public_key)
print("-------------------------------------------------------------------------------")

# create_Marks_table()
# insert_marks()

# match = re.search(r'Doctor: (.*?),Subject: (.*?),Marks: (.*?)$', message)
# if match:
#     Docter_name = match.group(1)
#     subject = match.group(2)
#     marks = match.group(3)


#  # Now you have the three variables (Docter_name, subject, marks)
#     print("Doctor:", Docter_name)
#     print("Subject:", subject)
#     print("Marks:", marks)
# else:
#     print("Invalid format for received message.")



# Split the message into components
# Split the message into components
# components = message.split(',')

# # Initialize variables
# Docter_name = None
# subject = None
# marks = None

# # Iterate over components to extract values
# for component in components:
#     # Split the component into key and value
#     key_value_pair = component.split(':')

#     # Check if there are exactly two parts (key and value)
#     if len(key_value_pair) == 2:
#         key, value = key_value_pair
#         key = key.strip()
#         value = value.strip()

#         if key == "Doctor":
#             Docter_name = value
#         elif key == "Subject":
#             subject = value
#         elif key == "Marks":
#             marks = value
#     else:
#         print(f"Ignoring invalid component: {component}")

# # Now you have the three variables (Docter_name, subject, marks)
# print("Doctor:", Docter_name)
# print("Subject:", subject)
# print("Marks:", marks)
components = message.split(',')

# Initialize variables
subject = None
marks = {}

# Iterate over components to extract values
for component in components:
    # Split the component into key and value
    key_value_pair = component.split(':')

    # Check if there are at least two parts (key and value)
    if len(key_value_pair) >= 2:
        # The first part is the key, and the rest are part of the value
        key = key_value_pair[0].strip()
        value = ':'.join(key_value_pair[1:]).strip()

        if key == "Subject":
            subject = value
        elif key == "Marks":
            # Split the Marks value into individual pairs
            mark_pairs = value.split(',')
            
            # Extract each student's name and marks
            students_data = [pair.split(':') for pair in mark_pairs]
            
            # Assuming you want to store marks as a dictionary
            marks = {student[0].strip(): int(student[1].strip()) for student in students_data}
            
    else:
        print(f"Ignoring invalid component: {component}")

# Print components and key-value pairs for debugging
print("Components:", components)
print("Key-Value Pairs:", [component.split(':') for component in components])

# Now you have the three variables (subject, marks)
print("Subject:", subject)
print("Marks:", marks)
insert_marks(verified_by,marks,subject,creation_time)

server_socket.close()