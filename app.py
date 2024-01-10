import tkinter as tk
import subprocess

def run_script1():
    subprocess.run(['python', 'account.py'])
    label.config(text="Create Account")

def run_script2():
    subprocess.run(['python', 'login.py'])
    label.config(text="Login")

def run_script3():
    subprocess.run(['python', 'info.py'])
    label.config(text="Complete Information")

def run_script4():
    subprocess.run(['python', 'PGP_c.py'])
    label.config(text="Send Projects")

def run_script5():
    subprocess.run(['python', 'Send_marks.py'])
    label.config(text="Send Marks")

def run_script6():
    subprocess.run(['python', 'show_marks.py'])
    label.config(text="Show marks")

# إعداد النافذة
window = tk.Tk()
window.title("Server Damascus University")

# إعداد العرض المتساوي للأزرار
button_width = 20

# إنشاء زرين
label = tk.Label(window, text="")
label.pack(pady=30)
# button_script5 = tk.Button(window, text="Start Server", command=run_server, width=button_width)
button_script1 = tk.Button(window, text="Create Account", command=run_script1, width=button_width)
button_script2 = tk.Button(window, text="Login", command=run_script2, width=button_width)
button_script3 = tk.Button(window, text="Complete Information", command=run_script3, width=button_width)
button_script4 = tk.Button(window, text="Send Projects", command=run_script4, width=button_width)
button_script5 = tk.Button(window, text="Send Marks", command=run_script5, width=button_width)
button_script6 = tk.Button(window, text="Show marks", command=run_script6, width=button_width)

# إضافة الأزرار إلى النافذة
# button_script5.pack(pady=10)
button_script1.pack(pady=10)
button_script2.pack(pady=10)
button_script3.pack(pady=10)
button_script4.pack(pady=10)
button_script5.pack(pady=10)
button_script6.pack(pady=10)
# إعداد عرض النافذة
window_width = 600  # تحديد عرض النافذة بالبكسل
window.geometry(f"{window_width}x400")

# إنشاء عنصر نصي للإشعار
label = tk.Label(window, text="")
label.pack(pady=20)

# تشغيل الحلقة الرئيسية للتطبيق
window.mainloop()
