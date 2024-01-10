import socket
from cryptography.hazmat.backends import default_backend
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
import hashlib
import random
import os
import ssl
print(ssl.OPENSSL_VERSION)

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
def convert_name(cryptography_name):
    name_attributes = []
    for attribute in cryptography_name:
        name_attributes.append(NameAttribute(attribute.oid, attribute.value))
    
    return Name(name_attributes)
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



# تكوين الـ socket
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_address = ('localhost', 12345)  # استخدم عنوان الخادم ورقم المنفذ الذي تحتاجه

# ربط الـ socket بعنوان الخادم
server_socket.bind(server_address)
server_socket.listen(1)

print('الخادم يستمع...')

# انتظار الاتصال من العميل
connection, client_address = server_socket.accept()
print('اتصال من', client_address)

# توليد زوج المفتاح
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
# subject = x509.Name([
#     x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
#     x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"CA"),
#     x509.NameAttribute(NameOID.LOCALITY_NAME, u"San Francisco"),
#     x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"MyOrg"),
#     x509.NameAttribute(NameOID.COMMON_NAME,u"Localhost"),
# ])

# csr = x509.CertificateSigningRequestBuilder().subject_name(
#     subject
# ).add_extension(
#     x509.BasicConstraints(ca=False, path_length=None), critical=True
# ).sign(private_key, hashes.SHA256(), default_backend())

# حفظ ملف CSR
# with open(os.path.join("CSR","server_csr.pem"), "wb") as f:
#     f.write(csr.public_bytes(serialization.Encoding.PEM))

def extract_certificate_type(cert):
    for extension in cert.extensions:
        if isinstance(extension.value, x509.SubjectAlternativeName):
            for name in extension.value:
                if isinstance(name, x509.DNSName):
                    return name.value  # لا داعي لاستخدام decode هنا

    return None

name_client = connection.recv(1024).decode()
print("name", name_client)
connection.sendall(pem)
# استقبال ملف CSR من العميل
print("public key ",pem)
received_csr = connection.recv(4096)
print(received_csr )
connection.sendall("a".encode())
signature = connection.recv(4096)
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
    
    # equation = generate_equation()
    # print("Generated Equation:", equation)
    # # equation = "2 * (3 + 15) + 10 -2 "  # يمكنك تعديل المعادلة حسب احتياجاتك
    # connection.sendall(equation.encode())
    # equation_result = eval(equation)
    # answer = hashlib.sha256(str(equation_result).encode()).hexdigest()
    # # الخطوة 3: استلام الإجابة من العميل
    # received_answer = connection.recv(4096).decode()
    # print("correct",answer)
    # print("answer",received_answer)

    # if received_answer== answer:
    #         print("correct.....")
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
    connection.sendall(cert_data )
        
except Exception as e:
        print("noooooooo")
        print(f"خطأ في التحقق: {e}")
# if verify_signature(public_key_client , signature , received_csr):
#      print("verify yesss........")
# else:
#    print("")
# فك تسلسل البيانات للحصول على كائن CertificateSigningRequest


# else :
#     print("you are client not doctor")
#     subject = csr.subject
#     signed_cert = x509.CertificateBuilder().subject_name(
#             subject
#         ).issuer_name(
#             subject
#         ).public_key(
#             csr.public_key()
#         ).serial_number(
#             x509.random_serial_number()
#         ).not_valid_before(
#             datetime.now(timezone.utc)  # تحديد وقت البداية
#         ).not_valid_after(
#             datetime.now(timezone.utc) + timedelta(days=3650)  # تاريخ انتهاء صالح لمدة 10 سنوات
#         ).add_extension(
#             x509.BasicConstraints(ca=False, path_length=None), critical=True
#         ).sign(private_key, hashes.SHA256(), default_backend())
        
#     # with open("signed_cert.pem", "wb") as f:
#     #     f.write(signed_cert.public_bytes(serialization.Encoding.PEM))
#     # with open("signed_cert.pem", "rb") as cert_file:
#     #     cert_data = cert_file.read()
#     # print(cert_data)
#     connection.sendall(signed_cert.public_bytes(serialization.Encoding.PEM))
# with open(os.path.join("CSR","server_csr.pem"), "rb") as csr_file:
#     csr_data = csr_file.read()
# csr_server = x509.load_pem_x509_csr(csr_data, default_backend())

# print(os.path.join("CSR","server_csr.pem"))
# print(keyfile=os.path.join("keys","private_key_server.pem"))
# print(os.path.join("CSR",f"{name_client}_csr.pem"))
# context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
# context.load_cert_chain(os.path.join("CSR","server_csr.pem"), keyfile=os.path.join("keys","private_key_server.pem"))
# context.verify_mode = ssl.CERT_REQUIRED
# context.load_verify_locations(cafile=os.path.join("CSR",f"{name_client}_csr.pem"))
# context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=os.path.join("CSR","server_csr.pem"))
# context.load_cert_chain(certfile=os.path.join("CSR",f"{name}_csr.pem"), keyfile=os.path.join("keys",f"{name}_private_key.pem"))
# context.verify_mode = ssl.CERT_REQUIRED

# حصول على الموضوع (Subject) من الـ CSR
# subject = convert_name(csr.subject)

# # إعداد الشهادة الموقعة
# signed_cert = crypto.X509()
# signed_cert.set_subject(subject)
# signed_cert.set_pubkey(csr.public_key().to_cryptography_key())
# signed_cert.gmtime_adj_notBefore(0)
# signed_cert.gmtime_adj_notAfter(315360000)  # تاريخ انتهاء صالح لمدة 10 سنوات
# signed_cert.sign(private_key, "sha256")
################################################################################################
# subject = csr.subject
# signed_cert = x509.CertificateBuilder().subject_name(
#         subject
#     ).issuer_name(
#         subject
#     ).public_key(
#         csr.public_key()
#     ).serial_number(
#         x509.random_serial_number()
#     ).not_valid_before(
#         datetime.now(timezone.utc)  # تحديد وقت البداية
#     ).not_valid_after(
#         datetime.now(timezone.utc) + timedelta(days=3650)  # تاريخ انتهاء صالح لمدة 10 سنوات
#     ).add_extension(
#         x509.BasicConstraints(ca=False, path_length=None), critical=True
#     ).sign(private_key, hashes.SHA256(), default_backend())
    
# with open("signed_cert.pem", "wb") as f:
#     f.write(signed_cert.public_bytes(serialization.Encoding.PEM))
# with open("signed_cert.pem", "rb") as cert_file:
#     cert_data = cert_file.read()
# print(cert_data)
# connection.sendall(cert_data )
        


