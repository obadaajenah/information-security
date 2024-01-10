
# import gnupg
# import tkinter as tk
# import socket
# import os
# import sqlite3
# import pickle
# import hashlib
# import json
# from cryptography.hazmat.primitives.asymmetric import padding
# from cryptography.hazmat.primitives import hashes
# from tkinter import messagebox
# from datetime import datetime



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

# Doctor_name = input("Enter the Doctor_name: ")
       
# email = f"{Doctor_name}@example.com"  # يمكنك تغيير البريد الإلكتروني حسب الحاجة
# passphrase = input("Enter your passphrase: ")
# path = r"C:\Program Files (x86)\GPG\GPG\GnuPG\bin\gpg.exe"
# home = r"C:\Users\Amera\Pictures\server\gpg"
# os.environ["GNUPGHOME"] = home
# gpg = gnupg.GPG(gnupghome=home)
# # client_key, private_key, finger =  generate_or_load_key(gpg, Doctor_name, email, passphrase)
# # # توليد مفتاح للدكتور الجامعي
# # # key_input = gpg.gen_key_input(name_email='doctor@example.com', passphrase='doctor_passphrase')
# # # key = gpg.gen_key(key_input)

# # # إنشاء CSR

# # # csr_data = gpg.export_keys(finger, secret=True, armor=True)
# # csr = gpg.gen_key_input(private_key)
# # csr_path = r"C:\Users\Amera\Pictures\server\CSR\csr.asc"
# # with open(csr_path, 'w') as csr_file:
# #     csr_file.write(str(csr))

# # with open(csr_path, 'r') as csr_file:
# #     csr_data = csr_file.read()

# # print(csr_data )
# # gpg = gnupg.GPG()

# # توليد مفتاح للدكتور الجامعي
# key_input = gpg.gen_key_input(name_email='doctor@example.com', passphrase='doctor_passphrase')
# key = gpg.gen_key(key_input)

# # إنشاء CSR
# csr_data = gpg.export_keys(key.fingerprint, secret=True, passphrase=passphrase)
# csr = gpg.gen_key_input(csr_data)
# csr_path =  r"C:\Users\Amera\Pictures\server\CSR\csr.asc"
# with open(csr_path, 'w') as csr_file:
#     csr_file.write(str(csr))

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
import socket
import hashlib
import tkinter as tk
from tkinter import messagebox
import os
from cryptography.x509 import load_pem_x509_certificate
from cryptography.hazmat.primitives.asymmetric import padding
import ssl
from cryptography import x509
import sqlite3
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import NameOID

from cryptography.hazmat.backends import default_backend
def get_marks(name_type):
    if os.path.exists(os.path.join("CSR",f"{name_type}_sign_sert.pem")):
        print(f"الشهادة  موجودة في المجلد.")
        db_path = 'your_database_file.db'
    
    # Connect to the SQLite database
        conn = sqlite3.connect("userdata.db")
        cur = conn.cursor()
        
        # Get the subject from the user
        subject = input("Enter the subject: ")
        
        # Query the 'marks' table to get marks for the subject
        cur.execute("SELECT * FROM marks WHERE subject=?", (subject,))
        marks_data = cur.fetchall()
        
        if marks_data:
            print(f"Marks for {subject}: {marks_data}")
            # Your logic to provide marks to the student goes here
        else:
            print(f"No marks found for {subject}.")
        
        # Close the database connection
        conn.close()
#     # اريد قراءة الprivate key ,public key من الملفات 
    else:
#     print(f"الشهادة غير موجودة في المجل.")
        print("Access granted. Provide marks to the student.")
    
def verify_signature(public_key, signature, data):
    try:
        public_key.verify(
            signature,
            data,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        
        return True
    except Exception as e:
        print(f"فشل في التحقق: {str(e)}")
        return False
def sign_data(private_key, data):
    try:
        # توقيع البيانات باستخدام مفتاح خاص
        signature = private_key.sign(
            data.encode('utf-8'),  # تحويل البيانات إلى بايت
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        return signature
    except Exception as e:
        print(f"فشل في التوقيع بسبب استثناء غير متوقع: {str(e)}")
        return None
class SendInfoApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Create CSR")

        self.label = tk.Label(root, text="Enter CSR information:", font=("Helvetica", 16))
        self.label.grid(row=0, column=0, columnspan=2, pady=10)

        self.username_label = tk.Label(root, text="Username:")
        self.username_label.grid(row=1, column=0, pady=5, padx=10, sticky="e")

        self.username_entry = tk.Entry(root, width=30)
        self.username_entry.grid(row=1, column=1, pady=5, padx=10)
        
        self.type_label = tk.Label(root, text="Type:")
        self.type_label.grid(row=2, column=0, pady=5, padx=10, sticky="e")
        
        self.type_entry = tk.Entry(root, width=30)
        self.type_entry.grid(row=2, column=1, pady=5, padx=10)

        self.city_label = tk.Label(root, text="Locality_City:")
        self.city_label.grid(row=3, column=0, pady=5, padx=10, sticky="e")

        self.city_entry = tk.Entry(root, width=30)
        self.city_entry.grid(row=3, column=1, pady=5, padx=10)


        self.create_button = tk.Button(root, text="Create", command=self.create_csr)
        self.create_button.grid(row=6, column=1,  pady=10, padx=40)
        
        


    def create_csr(self):
        name = self.username_entry.get()
        type = self.type_entry.get()
        name_type=f"{name}_{type}"

        locality = self.city_entry.get()
      
        filename= f"{name_type}_private_key.pem"

        
        # التحقق من وجود الاسم في القائمة
        # if filename in files:
        if os.path.exists(os.path.join("keys",f"{name_type}_private_key.pem")):
            print(f"الملف {filename} موجود في المجلد.")
            # اريد قراءة الprivate key ,public key من الملفات 
        else:
            print(f"الملف {filename} غير موجود في المجلد.")
            #اريد توليد المفاتيح وتخزينهم في ملفات 
        
        # توليد زوج المفتاح
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
                backend=default_backend()
            )

            # حفظ المفتاح العام والخاص
            pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            )

            with open(os.path.join("keys",f"{name_type}_private_key.pem"), "wb") as f:
                f.write(pem)

            public_key = private_key.public_key()
            pem = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )

            with open(os.path.join("keys",f"{name_type}_public_key.pem"), "wb") as f:
                f.write(pem)



        # قراءة المفتاح الخاص
        with open(os.path.join("keys",f"{name_type}_private_key.pem"), "rb") as key_file:
            private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=None,
                backend=default_backend()
            )
        with open(os.path.join("keys",f"{name_type}_public_key.pem"), "rb") as key_file:
            public_key = serialization.load_pem_public_key(
                    key_file.read(),
                    backend=default_backend()
                )
            public= public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo)
        # إنشاء ملف CSR
        # if os.path.exists(os.path.join("CSR",f"{name_type}_csr.pem")):
        #     print(f"الشهادة  موجودة في المجلد.")
        #     # اريد قراءة الprivate key ,public key من الملفات 
        # else:
        #     print(f"الشهادة غير موجودة في المجل.")
            print("okkkkkk1")
            subject = x509.Name([
                x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
                x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"CA"),
                x509.NameAttribute(NameOID.LOCALITY_NAME, locality),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME,u"Organization"),
                x509.NameAttribute(NameOID.COMMON_NAME, name),
            ])
            print("okkkkkk1")
            csr = x509.CertificateSigningRequestBuilder().subject_name(
            subject
        ).add_extension(
            x509.SubjectAlternativeName([x509.DNSName(type)]),
            critical=False,
        ).sign(private_key, hashes.SHA256(), default_backend())
            csr_bytes= csr.public_bytes(serialization.Encoding.PEM)
            print("okkkkkk1")
            # signature=sign_data(private_key , csr_bytes )
            signature = private_key.sign(csr_bytes, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
            print("okkkkkk1")
            print(  signature )
            # حفظ ملف CSR
        
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        with open("ip_address.txt", 'r') as file:
                  ip= file.read()

        with open("port.txt", 'r') as file:
            port  = file.read()
        port1=int(port)
        server_address = (ip,port1)  # استخدم عنوان الخادم ورقم المنفذ الذي تحتاجه

        # الاتصال بالخادم
        client_socket.connect(server_address)
        client_socket.sendall("csr".encode())
        a= client_socket.recv(1024)
        client_socket.sendall(name_type.encode())
        # استقبال المفتاح العام من الخادم
        public_key_server = client_socket.recv(4096)
        # ca_public_key = serialization.load_pem_public_key(public, backend=default_backend())
        csr_bytes2 = csr.public_bytes(serialization.Encoding.PEM)

        # الآن يمكنك إرسال csr_bytes باستخدام sendall
        print("okkkkkkkkkk")
        client_socket.sendall(csr_bytes)
        print("okkkkkkkkkk")
        a = client_socket.recv(1024).decode()
        client_socket.sendall(signature)
        print("okkkkkkkkkk_send")
        
        signed_cert = client_socket.recv(4096)
        with open(os.path.join("CSR",f"{name_type}_sign_sert.pem"), "wb") as f:
                f.write(signed_cert)
        print(signed_cert)
        tk.messagebox.showinfo("Create certificate", "Certificate created successfully!") 

       
root = tk.Tk()

# Create an instance of the CreateAccountApp
app = SendInfoApp(root)

# Run the Tkinter main loop
root.mainloop()        

# cert = load_pem_x509_certificate(signed_cert, default_backend())



# subject = cert.subject
# # # تحديد البيانات التي تم توقيعها بناءً على subject
# cert_data = cert.public_bytes(serialization.Encoding.PEM)

# # الحصول على بيانات التوقيع من الشهادة الموقعة
# signature = cert.signature
# with open(os.path.join("keys","public_key_server.pem"), 'rb') as ca_public_key_file:
#     ca_public_key_data = ca_public_key_file.read()
#     ca_public_key = serialization.load_pem_public_key(ca_public_key_data, backend=default_backend())
# # التحقق من التوقيع باستخدام مفتاح العميل العام
# if verify_signature(ca_public_key , signature, cert.tbs_certificate_bytes):
#     print(" Suceccfull verify by public key ...")
# else:
#     print("Faild verify ...")


    
    # Replace 'your_database_file.db' with the actual name of your SQLite database file
    









# print(os.path.join("CSR","server_csr.pem"))
# print(os.path.join("keys",f"{name}_private_key.pem"))
# print(os.path.join("CSR",f"{name}_csr.pem"))
# context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile="C:/Users/Amera/Pictures/server/CSR/server_csr.pem")
# context.load_cert_chain(certfile=os.path.join("CSR",f"{name}_csr.pem"), keyfile=os.path.join("keys",f"{name}_private_key.pem"))
# context.verify_mode = ssl.CERT_REQUIRED
# context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)

# context.load_cert_chain(certfile=os.path.join("CSR",f"{name}_csr.pem"), keyfile=os.path.join("keys",f"{name}_private_key.pem"))
# context.verify_mode = ssl.CERT_REQUIRED
# context.load_verify_locations(cafile=os.path.join("CSR","server_csr.pem"))