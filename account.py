# import tkinter as tk
# from tkinter import messagebox
# import sqlite3
# import hashlib

# def hash_password(password):
#     return hashlib.sha256(password.encode()).hexdigest()

# class CreateAccountApp:
#     def __init__(self, root):
#         self.root = root
#         self.root.title("Create Account")

#         self.label = tk.Label(root, text="Create a new account:", font=("Helvetica", 16))
#         self.label.grid(row=0, column=0, columnspan=2, pady=10)
#         self.ip_label = tk.Label(root, text="IP Address:")
#         self.ip_label.grid(row=1, column=0, pady=5, padx=10, sticky="e")

#         self.ip_entry = tk.Entry(root, width=30)
#         self.ip_entry.grid(row=1, column=1, pady=5, padx=10)
        
#         self.port_label = tk.Label(root, text="Port:")
#         self.port_label.grid(row=2, column=0, pady=5, padx=10, sticky="e")

#         self.port_entry = tk.Entry(root, width=30)
#         self.port_entry.grid(row=2, column=1, pady=5, padx=10)
#         # تسمية وإضافة حقل اسم المستخدم
#         self.username_label = tk.Label(root, text="Username:")
#         self.username_label.grid(row=3, column=0, pady=5, padx=10, sticky="e")

#         self.username_entry = tk.Entry(root, width=30)
#         self.username_entry.grid(row=3, column=1, pady=5, padx=10)

#         self.type_label = tk.Label(root, text="Type:")
#         self.type_label.grid(row=4, column=0, pady=5, padx=10, sticky="e")

#         self.type_entry = tk.Entry(root, width=30)
#         self.type_entry.grid(row=4, column=1, pady=5, padx=10)

#         # تسمية وإضافة حقل كلمة المرور
#         self.password_label = tk.Label(root, text="Password:")
#         self.password_label.grid(row=5, column=0, pady=5, padx=10, sticky="e")

#         self.password_entry = tk.Entry(root, width=30, show='*')
#         self.password_entry.grid(row=5, column=1, pady=5, padx=10)

#         self.create_button = tk.Button(root, text="Create Account", command=self.create_account)
#         self.create_button.grid(row=6, column=0, columnspan=2, pady=10)

#     def account_exists(self, username,type):
#         conn = sqlite3.connect("userdata.db")
#         cur = conn.cursor()
#         cur.execute("""
# CREATE TABLE IF NOT EXISTS userdata(
#     id INTEGER PRIMARY KEY,
#     username VARCHAR(255) NOT NULL,
#     password VARCHAR(255) NOT NULL,
#     type VARCHAR(255) NOT NULL        
# )             
# """)
#         cur.execute("SELECT * FROM userdata WHERE username=? AND type=?", (username, type))
#         result = cur.fetchone()
#         conn.close()
#         return result is not None

#     def create_account(self):
#         username = self.username_entry.get()
#         password = self.password_entry.get()
#         type = self.type_entry.get()
#         ip = self.ip_entry.get()
#         port= self.port_entry.get()
#         hashed_password = hash_password(password)
#         with open("ip_address.txt", "w") as f:
#                 f.write(ip)
#         with open("port.txt", "w") as f:
#                 f.write(port)

                
#         if self.account_exists(username,type):
#             tk.messagebox.showerror("Error", "Username already exists. Choose a different username.")
#             return

#         conn = sqlite3.connect("userdata.db")
#         cur = conn.cursor()
#         try:
#             cur.execute("INSERT INTO userdata (username, password,type) VALUES (?, ?,?)", (username, hashed_password,type))
#             conn.commit()
#             tk.messagebox.showinfo("Account Created", "Account created successfully!")
#             self.root.destroy()  # Close the window after account creation
#         except sqlite3.Error as e:
#             tk.messagebox.showerror("Error", f"Error creating account: {e}")

#         conn.close()

# # Create an instance of the Tkinter window
# root = tk.Tk()

# # Create an instance of the CreateAccountApp
# app = CreateAccountApp(root)

# # Run the Tkinter main loop
# root.mainloop()
import tkinter as tk
from tkinter import messagebox
import sqlite3
import hashlib
import threading
import socket
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

class CreateAccountApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Create Account")

        self.label = tk.Label(root, text="Create a new account:", font=("Helvetica", 16))
        self.label.grid(row=0, column=0, columnspan=2, pady=10)

        # تسمية وإضافة حقل اسم المستخدم
        self.ip_label = tk.Label(root, text="IP Address:")
        self.ip_label.grid(row=1, column=0, pady=5, padx=10, sticky="e")

        self.ip_entry = tk.Entry(root, width=30)
        self.ip_entry.grid(row=1, column=1, pady=5, padx=10)
        
        self.port_label = tk.Label(root, text="Port:")
        self.port_label.grid(row=2, column=0, pady=5, padx=10, sticky="e")

        self.port_entry = tk.Entry(root, width=30)
        self.port_entry.grid(row=2, column=1, pady=5, padx=10)
        # تسمية وإضافة حقل اسم المستخدم
        self.username_label = tk.Label(root, text="Username:")
        self.username_label.grid(row=3, column=0, pady=5, padx=10, sticky="e")

        self.username_entry = tk.Entry(root, width=30)
        self.username_entry.grid(row=3, column=1, pady=5, padx=10)

        self.type_label = tk.Label(root, text="Type:")
        self.type_label.grid(row=4, column=0, pady=5, padx=10, sticky="e")

        self.type_entry = tk.Entry(root, width=30)
        self.type_entry.grid(row=4, column=1, pady=5, padx=10)

        # تسمية وإضافة حقل كلمة المرور
        self.password_label = tk.Label(root, text="Password:")
        self.password_label.grid(row=5, column=0, pady=5, padx=10, sticky="e")

        self.password_entry = tk.Entry(root, width=30, show='*')
        self.password_entry.grid(row=5, column=1, pady=5, padx=10)

        self.create_button = tk.Button(root, text="Create Account", command=self.create_account)
        self.create_button.grid(row=6, column=0, columnspan=2, pady=10)

#     def account_exists(self, username,type):
#         conn = sqlite3.connect("userdata.db")
#         cur = conn.cursor()
#         cur.execute("""
# CREATE TABLE IF NOT EXISTS userdata(
#     id INTEGER PRIMARY KEY,
#     username VARCHAR(255) NOT NULL,
#     password VARCHAR(255) NOT NULL,
#     type VARCHAR(255) NOT NULL        
# )             
# """)
#         cur.execute("SELECT * FROM userdata WHERE username=? AND type=?", (username, type))
#         result = cur.fetchone()
#         conn.close()
#         return result is not None

    def create_account(self):
        username = self.username_entry.get()
        password = self.password_entry.get()
        type = self.type_entry.get()
        ip = self.ip_entry.get()
        port= self.port_entry.get()
        hashed_password = hash_password(password)
        print(username)
        print(password)
        print(type)
        
        with open("ip_address.txt", "w") as f:
                f.write(ip)
        with open("port.txt", "w") as f:
                f.write(port)
      
        threading.Thread(target=self.perform_login, args=(username, password,type)).start()

    def perform_login(self, username, password,type):
        with open("ip_address.txt", 'r') as file:
                ip= file.read()

        with open("port.txt", 'r') as file:
            port  = file.read()
                
        try:
            port1=int(port)
            
            client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client_socket .connect((ip, port1))
            client_socket.send("account".encode())
            
            client_socket.recv(1024).decode()
        
            client_socket.send(username.encode())
            client_socket.recv(1024).decode()

            
            client_socket.send(type.encode())
            client_socket.recv(1024).decode()
            client_socket.send(password.encode())
            
        except Exception as e:
            messagebox.showerror("Error", f"Error during login: {e}")


            
# Create an instance of the Tkinter window
root = tk.Tk()

# Create an instance of the CreateAccountApp
app = CreateAccountApp(root)

# Run the Tkinter main loop
root.mainloop()