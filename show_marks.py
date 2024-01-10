import tkinter as tk
from tkinter import messagebox
from tkinter import ttk
import os
import sqlite3
class SendInfoApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Show marks")

        self.label = tk.Label(root, text="Enter information to show marks:", font=("Helvetica", 16))
        self.label.grid(row=0, column=0, columnspan=2, pady=10)

        self.username_label = tk.Label(root, text="your_name:")
        self.username_label.grid(row=1, column=0, pady=5, padx=10, sticky="e")

        self.username_entry = tk.Entry(root, width=30)
        self.username_entry.grid(row=1, column=1, pady=5, padx=10)
        
        self.subject_label = tk.Label(root, text="subject_name:")
        self.subject_label.grid(row=2, column=0, pady=5, padx=10, sticky="e")

        self.subject_entry = tk.Entry(root, width=30)
        self.subject_entry.grid(row=2, column=1, pady=5, padx=10)


        self.create_button = tk.Button(root, text="Get Marks", command=self.show_table)
        self.create_button.grid(row=6, column=1,  pady=10, padx=40)
        
      


    def show_table(self):
        name = self.username_entry.get()
        subject = self.subject_entry.get()
        if os.path.exists(os.path.join("CSR",f"{name}_doctor_sign_sert.pem")):
            print(f"الشهادة  موجودة في المجلد.")
            conn = sqlite3.connect("userdata.db")
            cur = conn.cursor()
        # إعداد الواجهة الرسومية
            root = tk.Tk()
            root.title(" Table Marks")

            # العناوين للأعمدة
            columns = [" Doctor name", "Subject", "Marks"]

            # إنشاء جدول
            tree = ttk.Treeview(root, columns=columns, show="headings")

            # تحديد أنواع الأعمدة
            for col in columns:
                tree.heading(col, text=col)
                tree.column(col, anchor="center")

            cur.execute("SELECT Docter_name, subject, marks FROM marks WHERE subject=?", (subject,))
            # جلب البيانات
            data = cur.fetchall()
        
            # إدراج البيانات في الجدول
            for row in data:
                tree.insert("", "end", values=row)

            # تحديد حجم النافذة
            root.geometry("600x250")

            # عرض الجدول
            tree.pack()

            # تشغيل الواجهة الرسومية
            root.mainloop()
            conn.close()

        else:
            tk.messagebox.showerror("Error", "Access granted. Provide marks to the student.")
            print("Access granted. Provide marks to the student.")
    # افتتاح اتصال بقاعدة البيانات
    # conn = sqlite3.connect("اسم_قاعدة_البيانات.db")
    # cur = conn.cursor()

    # تعيين الموضوع المطلوب
  

    # عرض البيانات كجدول
    

    # إغلاق اتصال قاعدة البيانات
    

    def show_marks(self):
        name = self.username_entry.get()
        subject = self.subject_entry.get()
        if os.path.exists(os.path.join("CSR",f"{name}_doctor_sign_sert.pem")):
                print(f"الشهادة  موجودة في المجلد.")
                db_path = 'your_database_file.db'
            
            # Connect to the SQLite database
                conn = sqlite3.connect("userdata.db")
                cur = conn.cursor()
                
                # Get the subject from the user
                # subject = input("Enter the subject: ")
                
                # Query the 'marks' table to get marks for the subject
                cur.execute("SELECT * FROM marks WHERE subject=?", (subject,))
                marks_data = cur.fetchall()
                
                if marks_data:
                    tk.messagebox.showinfo("Marks", f"Marks for {subject}: {marks_data}")
                    print(f"Marks for {subject}: {marks_data}")
                    for row in marks_data:
                        id, doctor_name, subject, marks, id_generation, timestamp = row
                        print(f"ID: {id}, Doctor Name: {doctor_name}, Subject: {subject}, Marks: {marks}, ID Generation: {id_generation}, Timestamp: {timestamp}")

                    # Your logic to provide marks to the student goes here
                else:
                    tk.messagebox.showerror("Error", f"No marks found for {subject}.")
                    print(f"No marks found for {subject}.")
                
                # Close the database connection
                conn.close()
        #     # اريد قراءة الprivate key ,public key من الملفات 
        else:
    #     print(f"الشهادة غير موجودة في المجل.")
            tk.messagebox.showerror("Error", "Access granted. Provide marks to the student.")
            print("Access granted. Provide marks to the student.")

root = tk.Tk()

# Create an instance of the CreateAccountApp
app = SendInfoApp(root)

# Run the Tkinter main loop
root.mainloop()