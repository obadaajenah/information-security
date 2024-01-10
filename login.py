import tkinter as tk
from tkinter import messagebox
import socket
import threading
import subprocess
import hashlib
import os
from tkinter import *
class LoginApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Login System")

        self.label = tk.Label(root, text="Login System", font=("Helvetica", 16))
        self.label.grid(row=0, column=0, columnspan=2, pady=10)
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

        self.login_button = tk.Button(root, text="Login", command=self.login)
        self.login_button.grid(row=6, column=0, columnspan=2, pady=10)
        # self.label.pack(pady=10)

        # self.username_entry = tk.Entry(root, width=30)
        # self.username_entry.pack(pady=5)

        # self.password_entry = tk.Entry(root, width=30, show='*')
        # self.password_entry.pack(pady=5)

        # self.login_button = tk.Button(root, text="Login", command=self.login)
        # self.login_button.pack(pady=10)
    
    def login(self):
        # Get username and password from entry widgets
        ip = self.ip_entry.get()
        port= self.port_entry.get()
        username = self.username_entry.get()
        password = self.password_entry.get()
        type = self.type_entry.get()
        with open("ip_address.txt", "w") as f:
                f.write(ip)
        with open("port.txt", "w") as f:
                f.write(port)
        # import module
        # module.ip_address = ip
        # module.port = port
        # subprocess.run(['python', 'equation.py'])
        # Create a new thread for networking operations
        threading.Thread(target=self.perform_login, args=(username, password,type)).start()

    def perform_login(self, username, password,type):
        with open("ip_address.txt", 'r') as file:
                ip= file.read()

        with open("port.txt", 'r') as file:
            port  = file.read()
                
        # try:
            port1=int(port)
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:

                client.connect((ip, port1))
                client.send("login".encode())
                # client.send("Username:".encode())
                client.recv(1024).decode()
           
                client.send(username.encode())
                client.recv(1024).decode()

                # client.send("Password:".encode())
                # client.recv(1024).decode()
                client.send(type.encode())
                client.recv(1024).decode()
                client.send(password.encode())
                # client.recv(1024).decode()
             
                response = client.recv(1024).decode()
                name_type=f"{username}_{type}"
                print(response)
                messagebox.showinfo("Login Result", response)
                if type =="doctor":
                    if os.path.exists(os.path.join("CSR",f"{name_type}_sign_sert.pem")):
                            print(f"الشهادة  موجودة في المجلد.")
                    else:
                            received_equation = client.recv(4096).decode()
                            
                            # equation_result=""
                            window = tk.Tk()
                            window.title(" Solve Equation")
                            spacer_frame = tk.Frame(window, height=20)
                            spacer_frame.pack()
                            # إضافة جملة إلى الواجهة
                            label = tk.Label(window, text=f" Solve this  Equation: { received_equation}")
                            # label = tk.Label(window, text=)
                            label.pack()
                            spacer_frame = tk.Frame(window, height=20)
                            spacer_frame.pack()
                            equation_r = StringVar()
                            # حقل إدخال نص
                            entry = tk.Entry(window, textvariable=equation_r)
                            entry.pack()
                            spacer_frame = tk.Frame(window, height=20)
                            spacer_frame.pack()
                            # زر
                            button = tk.Button(window, text=" send answer" , command=lambda: (
                            equation_r.set(entry.get()),  # تعليمة الاسناد
                        
                            # قم بإضافة التعليمات الإضافية هنا
                            window.destroy()  # لإغلاق النافذة
            ))# لإغلاق النافذة
                        
                            button.pack()
                            spacer_frame = tk.Frame(window, height=20)
                            spacer_frame.pack()
                            label_result = tk.Label(window, text="")
                            label_result.pack()

                            window.geometry("250x200")
                            window.update_idletasks()
                            screen_width = window.winfo_screenwidth()
                            screen_height = window.winfo_screenheight()
                            x_coordinate = (screen_width - window.winfo_reqwidth()) // 2
                            y_coordinate = (screen_height - window.winfo_reqheight()) // 2
                            window.geometry(f"+{x_coordinate}+{y_coordinate}")
                            
                            # تشغيل الواجهة
                            window.mainloop()  
                        # def on_button_click():
                        #   ans = entry.get()
                        #   label_result.config(text=f"your Answer is correct")
                        #   print("Solve this equation :", received_equation.decode())
                        
                            # الخطوة 3: حل المعادلة وإرسال الإجابة
                            # equation_result = input(f"Enter the correct answer to solve this equation {received_equation.decode()} : ")
                            # equation_result = eval(received_equation.decode())
                            equation_result=equation_r.get()
                            print("mmmmm",  equation_result)
                            answer = hashlib.sha256(str(equation_result).encode()).hexdigest()
                            client.sendall(answer.encode())
                            
                            print(equation_result)
                            print(answer)
                
        # except Exception as e:
        #     messagebox.showerror("Error", f"Error during login: {e}")
            # self.root.destroy() 
# Create an instance of the Tkinter window
root = tk.Tk()

# Create an instance of the LoginApp
app = LoginApp(root)

# Run the Tkinter main loop
root.mainloop()
