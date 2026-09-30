import binascii
import tkinter as tk
from tkinter import filedialog, messagebox
from cryptography.exceptions import InvalidTag
from securecrypto import aes_utils


def show_result(text):
    # Hiện kết quả trong Entry chỉ-đọc: bôi đen / Ctrl+C được (Label thì không copy được)
    result_entry.config(state="normal")
    result_entry.delete(0, tk.END)
    result_entry.insert(0, text)
    result_entry.config(state="readonly")


def encrypt():
    pw = password_entry.get()
    if not pw:
        messagebox.showerror("Lỗi", "Hãy nhập Password trước khi Encrypt.")
        return
    file = filedialog.askopenfilename(title="Chọn file cần mã hoá")
    if not file:  # bấm Cancel ở hộp chọn file
        return
    try:
        key = aes_utils.encrypt_file_aes(file, pw)
    except OSError as e:
        messagebox.showerror("Lỗi", f"Không mã hoá được file:\n{e}")
        return
    show_result(key)
    root.clipboard_clear()
    root.clipboard_append(key)
    messagebox.showinfo("Encrypt",
                        f"Đã tạo: {file}.enc\n\n"
                        "Key đã được copy vào clipboard.\n"
                        "Dán Key này vào ô 'Key' để giải mã.")


def decrypt():
    key = key_entry.get().strip()
    if not key:
        messagebox.showerror("Lỗi", "Hãy dán Key (base64) nhận được khi Encrypt.")
        return
    file = filedialog.askopenfilename(title="Chọn file .enc cần giải mã",
                                      filetypes=[("Encrypted file", "*.enc"),
                                                 ("All files", "*.*")])
    if not file:
        return
    try:
        out = aes_utils.decrypt_file_aes(file, key)
    except (binascii.Error, ValueError):
        messagebox.showerror("Lỗi",
                             "Key không hợp lệ: phải là chuỗi base64 44 ký tự "
                             "nhận được khi Encrypt (không phải Password).")
        return
    except InvalidTag:
        messagebox.showerror("Lỗi",
                             "Giải mã thất bại: sai Key hoặc file .enc đã bị sửa đổi.")
        return
    except OSError as e:
        messagebox.showerror("Lỗi", f"Không đọc/ghi được file:\n{e}")
        return
    show_result(out)
    messagebox.showinfo("Decrypt", f"Giải mã thành công:\n{out}")


root = tk.Tk()
root.title("SecureCrypto GUI")
root.minsize(460, 0)

tk.Label(root, text="Password (dùng khi Encrypt):").pack(anchor="w", padx=10, pady=(10, 0))
password_entry = tk.Entry(root, show="*", width=50)
password_entry.pack(padx=10)
tk.Button(root, text="Encrypt", command=encrypt).pack(pady=5)

tk.Label(root, text="Key base64 (dùng khi Decrypt):").pack(anchor="w", padx=10)
key_entry = tk.Entry(root, width=50)
key_entry.pack(padx=10)
tk.Button(root, text="Decrypt", command=decrypt).pack(pady=5)

tk.Label(root, text="Kết quả (bôi đen để copy):").pack(anchor="w", padx=10)
result_entry = tk.Entry(root, width=50, state="readonly")
result_entry.pack(padx=10, pady=(0, 10))

root.mainloop()
