import tkinter as tk
from tkinter import messagebox, simpledialog
import pyperclip
from encryption_utils import generate_key, SALT_SIZE
from user_auth import register_user, authenticate_user
from password_manager import save_password, search_password, update_password, delete_password, generate_random_password


class PasswordManagerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Password Manager")

        # Frames
        self.login_frame = tk.Frame(self.root)
        self.main_frame = tk.Frame(self.root)
        self.password_frame = tk.Frame(self.root)

        self.create_login_frame()

    def create_login_frame(self):
        self.clear_frame(self.login_frame)

        tk.Label(self.login_frame, text="Username:").pack()
        self.username_entry = tk.Entry(self.login_frame)
        self.username_entry.pack()

        tk.Label(self.login_frame, text="Password:").pack()
        self.password_entry = tk.Entry(self.login_frame, show="*")
        self.password_entry.pack()

        tk.Button(self.login_frame, text="Login", command=self.login).pack()
        tk.Button(self.login_frame, text="Register", command=self.register).pack()

        self.login_frame.pack()

    def login(self):
        username = self.username_entry.get()
        password = self.password_entry.get()
        if authenticate_user(username, password):
            self.master_key = generate_key(password, username.encode()[:SALT_SIZE])
            self.create_main_frame()
        else:
            messagebox.showerror("Error", "Invalid username or password")

    def register(self):
        username = self.username_entry.get()
        password = self.password_entry.get()
        if register_user(username, password):
            messagebox.showinfo("Success", "User registered successfully")
        else:
            messagebox.showerror("Error", "Username already exists")

    def create_main_frame(self):
        self.clear_frame(self.main_frame)

        tk.Button(self.main_frame, text="Add Password", command=self.add_password).pack()
        tk.Button(self.main_frame, text="Search Password", command=self.search_password).pack()
        tk.Button(self.main_frame, text="Update Password", command=self.update_password).pack()
        tk.Button(self.main_frame, text="Delete Password", command=self.delete_password).pack()
        tk.Button(self.main_frame, text="Generate Random Password", command=self.generate_random_password_ui).pack()
        tk.Button(self.main_frame, text="Logout", command=self.logout).pack()

        self.main_frame.pack()

    def add_password(self):
        self.clear_frame(self.password_frame)

        tk.Label(self.password_frame, text="Title:").pack()
        self.title_entry = tk.Entry(self.password_frame)
        self.title_entry.pack()

        tk.Label(self.password_frame, text="Password:").pack()
        self.password_entry = tk.Entry(self.password_frame)
        self.password_entry.pack()

        tk.Label(self.password_frame, text="URL/Application:").pack()
        self.url_entry = tk.Entry(self.password_frame)
        self.url_entry.pack()

        tk.Label(self.password_frame, text="Other Info:").pack()
        self.other_info_entry = tk.Entry(self.password_frame)
        self.other_info_entry.pack()

        tk.Button(self.password_frame, text="Save", command=self.save_password_ui).pack()
        tk.Button(self.password_frame, text="Back", command=self.create_main_frame).pack()

        self.password_frame.pack()

    def save_password_ui(self):
        title = self.title_entry.get()
        password = self.password_entry.get()
        url = self.url_entry.get()
        other_info = self.other_info_entry.get()
        save_password(title, password, url, other_info, self.master_key)
        messagebox.showinfo("Success", "Password saved successfully")
        self.create_main_frame()

    def search_password(self):
        title = simpledialog.askstring("Search Password", "Enter title:")
        result = search_password(title, self.master_key)
        if result:
            title, password, url, other_info = result
            self.clear_frame(self.password_frame)

            tk.Label(self.password_frame, text=f"Title: {title}").pack()
            tk.Label(self.password_frame, text=f"URL/Application: {url}").pack()
            tk.Label(self.password_frame, text=f"Other Info: {other_info}").pack()

            tk.Label(self.password_frame, text="Password:").pack()
            self.password_label = tk.Label(self.password_frame, text="******")
            self.password_label.pack()

            tk.Button(self.password_frame, text="Show", command=lambda: self.password_label.config(text=password)).pack()
            tk.Button(self.password_frame, text="Copy to Clipboard", command=lambda: pyperclip.copy(password)).pack()
            tk.Button(self.password_frame, text="Back", command=self.create_main_frame).pack()

            self.password_frame.pack()
        else:
            messagebox.showerror("Error", "Password not found")

    def update_password(self):
        title = simpledialog.askstring("Update Password", "Enter title:")
        result = search_password(title, self.master_key)
        if result:
            new_password = simpledialog.askstring("Update Password", "Enter new password:")
            if update_password(title, new_password, self.master_key):
                messagebox.showinfo("Success", "Password updated successfully")
            else:
                messagebox.showerror("Error", "Error updating password")
        else:
            messagebox.showerror("Error", "Password not found")

    def delete_password(self):
        title = simpledialog.askstring("Delete Password", "Enter title:")
        if delete_password(title):
            messagebox.showinfo("Success", "Password deleted successfully")
        else:
            messagebox.showerror("Error", "Password not found")

    def generate_random_password_ui(self):
        length = simpledialog.askinteger("Random Password", "Enter length:", minvalue=8, maxvalue=64)
        password = generate_random_password(length)
        messagebox.showinfo("Random Password", f"Generated Password: {password}")
        pyperclip.copy(password)

    def logout(self):
        self.master_key = None
        self.create_login_frame()

    def clear_frame(self, frame):
        for widget in frame.winfo_children():
            widget.destroy()
        frame.pack_forget()

if __name__ == "__main__":
    root = tk.Tk()
    app = PasswordManagerApp(root)
    root.mainloop()

