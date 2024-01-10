# # import tkinter as tk
# # import socket
# # import json

# # class GradeApp:
# #     def __init__(self, root):
# #         self.root = root
# #         self.root.title("Grade App")

# #         self.username_label = tk.Label(root, text="اسم المستخدم:")
# #         self.username_label.grid(row=0, column=0, pady=5, padx=10, sticky="e")

# #         self.username_entry = tk.Entry(root, width=30)
# #         self.username_entry.grid(row=0, column=1, pady=5, padx=10)

# #         self.subject_label = tk.Label(root, text="المادة:")
# #         self.subject_label.grid(row=1, column=0, pady=5, padx=10, sticky="e")

# #         self.subject_entry = tk.Entry(root, width=30)
# #         self.subject_entry.grid(row=1, column=1, pady=5, padx=10)

# #         self.grade_label = tk.Label(root, text="العلامة:")
# #         self.grade_label.grid(row=2, column=0, pady=5, padx=10, sticky="e")

# #         self.grade_entry = tk.Entry(root, width=30)
# #         self.grade_entry.grid(row=2, column=1, pady=5, padx=10)

# #         self.add_button = tk.Button(root, text="إضافة", command=self.add_grade)
# #         self.add_button.grid(row=3, column=0, columnspan=2, pady=10)

# #         self.send_button = tk.Button(root, text="إرسال", command=self.send_grades)
# #         self.send_button.grid(row=4, column=0, columnspan=2, pady=10)

# #         # قائمة لتخزين الأزواج (المادة، العلامة)
# #         self.grades_list = []

# #     def add_grade(self):
# #         subject = self.subject_entry.get()
# #         grade = self.grade_entry.get()

# #         # إضافة الزوج (المادة، العلامة) إلى القائمة
# #         self.grades_list.append((subject, grade))

# #         # مسح المدخلات
# #         self.subject_entry.delete(0, 'end')
# #         self.grade_entry.delete(0, 'end')

# #     def send_grades(self):
# #         username = self.username_entry.get()

# #         # تحويل القائمة إلى JSON لنقلها بسهولة
# #         grades_json = json.dumps(self.grades_list)
# #         print(grades_json)
# #         # Establish a connection to the server
# #         # server_address = ('127.0.0.1', 8888)
# #         # client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
# #         # client_socket.connect(server_address)

# #         # # Send username to server
# #         # client_socket.sendall(username.encode('utf-8'))

# #         # # Send grades list to server
# #         # client_socket.sendall(grades_json.encode('utf-8'))

# #         # # Close the client socket
# #         # client_socket.close()

# # # إنشاء تطبيق GradeApp وتشغيل الواجهة
# # root = tk.Tk()
# # app = GradeApp(root)
# # root.mainloop()



# import sqlite3

# # Create a connection to the SQLite database
# connection = sqlite3.connect('userdata.db')
# cursor = connection.cursor()
# # cursor.execute('DROP TABLE IF EXISTS subject')
# cursor.execute("""
#                CREATE TABLE subject (
#     id INT PRIMARY KEY ,
#     name VARCHAR(50),
#     marks TEXT
# );""")

# # Sample data
# student_data = [
#     ('John', [90, 85, 95]),
#     ('Alice', [88, 92, 89]),
#     ('Bob', [75, 80, 78])
# ]

# # Insert data into the table
# for name, marks in student_data:
#     cursor.execute("INSERT INTO subject (name, marks) VALUES (?, ?)", (name, ','.join(map(str, marks))))

# # Commit the changes and close the connection
# connection.commit()
# connection.close()

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import gnupg
import socket
import os
import json
import pickle
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
def insert_marks( Docter_name, marks, subject, ID_generation):
    try:
        # Create a connection and cursor
        conn = sqlite3.connect("userdata.db")
        cur = conn.cursor()
       
        
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        # Execute the SQL query with the converted marks
        cur.execute('''
         INSERT INTO marks (Docter_name, marks, subject, ID_generation, timestamp)
         VALUES (?, ?, ?, ?, ?);
        ''', (Docter_name, marks, subject, ID_generation, timestamp))

        # Commit the changes
        conn.commit()
        print("Record inserted into the marks table.")

    finally:
        # Close the cursor and connection in a finally block to ensure they are closed
        cur.close()
        conn.close()

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
    cur.execute('''
        INSERT INTO marks (Docter_name,marks,subject,ID_generation,timestamp)
        VALUES (?, ?, ?,?,?)
    ''', (Docter_name,marks,subject,ID_generation,timestamp ))
    conn.commit()


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

path = r"C:\Program Files (x86)\GPG\GPG\GnuPG\bin\gpg.exe"
home = r"C:\Users\Amera\Pictures\server\gpg"
os.environ["GNUPGHOME"] = home

# Specify the GPG binary path
gpg = gnupg.GPG(gnupghome=home, gpgbinary=path)

# تكوين المأخذ
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind(('localhost', 12345))  # اختر رقم المنفذ الذي تريده
server_socket.listen(1)
# conn = sqlite3.connect("userdata.db")
# cur = conn.cursor()

#         # Execute SQL to drop the table if it exists
# cur.execute('DROP TABLE IF EXISTS marks')

#         # Commit the changes
# conn.commit()
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

# create_Marks_table()

print("--------------1-------------")
received_encrypted_signature = client_socket.recv(1024)

print(received_encrypted_signature)
signature = decrypt_message(gpg,received_encrypted_signature)
print("--------------2------------")
print("Received and Decrypted Message from client:",signature)
print("----------------------------------------------")
# received_encrypted_message = client_socket.recv(1024)
# recv = json.loads(received_encrypted_message)
# print(received_encrypted_message)
# message = decrypt_message(gpg,received_encrypted_message)
# print("Received and Decrypted Message from client:",message)
  # message = {
        #     "doctor_name": doctor_name,
        #     "subject_name": subject_name,
        #     "marks": marks
        #     }
data = client_socket.recv(8192)
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
# encrypted_subject_name = recv["subject_name"]
# encrypted_marks = recv["marks"]
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




server_socket.close()