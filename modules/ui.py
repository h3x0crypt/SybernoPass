import tkinter as tk
from tkinter import messagebox, simpledialog, Listbox, Toplevel
from modules.password_manager import PasswordManager
from modules.file_manager import FileManager


class UI:
    def __init__(self, root):
        self.root = root
        self.manager = PasswordManager()
        self.file_manager = FileManager()
        self.gen_window = None
        self.entry_keywords = None
        self.entry_date = None
        self.entry_generated_password = None
        self.setup_login()

    def center_window(self, window, width_percent, height_percent):
        screen_width = window.winfo_screenwidth()
        screen_height = window.winfo_screenheight()

        window_width = int(screen_width * width_percent)
        window_height = int(screen_height * height_percent)

        position_x = (screen_width // 2) - (window_width // 2)
        position_y = (screen_height // 2) - (window_height // 2)

        window.geometry(f"{window_width}x{window_height}+{position_x}+{position_y}")

    def setup_login(self):
        self.root.title("SybernoPass - Login")
        self.center_window(self.root, 0.3, 0.3)

        label_username = tk.Label(self.root, text="Username:")
        label_username.pack(pady=5)
        entry_username = tk.Entry(self.root, width=30)
        entry_username.pack(pady=5)

        label_password = tk.Label(self.root, text="Password:")
        label_password.pack(pady=5)
        entry_password = tk.Entry(self.root, width=30, show='*')
        entry_password.pack(pady=5)

        btn_login = tk.Button(self.root, text="Login",
                              command=lambda: self.authenticate(entry_username, entry_password))
        btn_login.pack(pady=20)

    def authenticate(self, entry_username, entry_password):
        username = entry_username.get()
        password = entry_password.get()
        if username == "admin" and password == "password":
            messagebox.showinfo("Login Success", "Welcome!")
            self.root.destroy()
            self.show_password_generator()
        else:
            messagebox.showerror("Login Failed", "Invalid username or password")

    def show_password_generator(self):
        self.gen_window = tk.Tk()
        self.gen_window.title("Password Generator")
        self.center_window(self.gen_window, 0.3, 0.3)  # Set the size to 30% of the screen width and height

        label_keywords = tk.Label(self.gen_window, text="Enter Keywords (comma separated):")
        label_keywords.pack(pady=5)
        self.entry_keywords = tk.Entry(self.gen_window, width=50)
        self.entry_keywords.pack(pady=5)

        label_date = tk.Label(self.gen_window, text="Enter Date:")
        label_date.pack(pady=5)
        self.entry_date = tk.Entry(self.gen_window, width=50)
        self.entry_date.pack(pady=5)

        btn_generate = tk.Button(self.gen_window, text="Generate Password", command=self.on_generate)
        btn_generate.pack(pady=20)

        btn_view = tk.Button(self.gen_window, text="View Saved Passwords", command=self.view_saved_passwords)
        btn_view.pack(pady=20)

        self.gen_window.mainloop()

    def show_decrypted_password(self, title, decrypted_password):
        dialog = Toplevel(self.gen_window)
        dialog.title("Decrypted Password")
        self.center_window(dialog, 0.4, 0.2)

        label_title = tk.Label(dialog, text=f"Title: {title}")
        label_title.pack(pady=5)

        label_password = tk.Label(dialog, text="Password:")
        label_password.pack(pady=5)

        entry_password = tk.Entry(dialog, width=50)
        entry_password.pack(pady=5)
        entry_password.insert(0, decrypted_password)
        entry_password.config(state='readonly')  # Set state to readonly after inserting the password

        def copy_to_clipboard():
            dialog.clipboard_clear()
            dialog.clipboard_append(decrypted_password)
            dialog.update()  # Now it stays on the clipboard after the window is closed
            messagebox.showinfo("Copied", "Password copied to clipboard.", parent=dialog)

        btn_copy = tk.Button(dialog, text="Copy", command=copy_to_clipboard)
        btn_copy.pack(pady=5)

        def close_dialog():
            dialog.destroy()

        btn_close = tk.Button(dialog, text="Close", command=close_dialog)
        btn_close.pack(pady=10)

    def on_generate(self):
        keywords = self.entry_keywords.get().split(',')
        date = self.entry_date.get()
        password = self.manager.generate_password(keywords, date)

        if not self.file_manager.load_master_passphrase_hash():
            passphrase = simpledialog.askstring("Set Passphrase", "Enter a passphrase to set as master passphrase:",
                                                show='*')
            if passphrase:
                self.file_manager.save_master_passphrase_hash(self.manager.hash_passphrase(passphrase))
                self.file_manager.generate_and_save_rsa_keys(passphrase)
        else:
            passphrase = simpledialog.askstring("Confirm Passphrase",
                                                "Enter your master passphrase to add a new password:", show='*')
            stored_hash = self.file_manager.load_master_passphrase_hash()
            if not self.manager.verify_master_passphrase(passphrase, stored_hash):
                messagebox.showerror("Error", "Incorrect passphrase.")
                return

        self.gen_window.lift()  # Bring the window to the foreground
        title = simpledialog.askstring("Title", "Enter a title for your password:", parent=self.gen_window)
        if title:
            private_key_pem, public_key_pem = self.file_manager.load_rsa_keys()
            encrypted_password = self.manager.encrypt_password(public_key_pem, password, title)
            self.file_manager.save_password(title, encrypted_password)
            self.show_decrypted_password(title, password)

    def view_saved_passwords(self):
        def show_selected_password():
            selected = selected_password.get()
            if not selected:
                messagebox.showwarning("Warning", "No password selected")
                return
            passphrase = simpledialog.askstring("Passphrase", "Enter your master passphrase to decrypt the password:",
                                                show='*')
            if passphrase:
                stored_hash = self.file_manager.load_master_passphrase_hash()
                if not self.manager.verify_master_passphrase(passphrase, stored_hash):
                    messagebox.showerror("Error", "Incorrect passphrase.")
                    return
                try:
                    private_key_pem, _ = self.file_manager.load_rsa_keys()
                    passwords = self.file_manager.load_passwords()
                    for data in passwords:
                        if data["title"] == selected:
                            encrypted_password = bytes.fromhex(data["encrypted_password"])
                            decrypted_password = self.manager.decrypt_password(private_key_pem, encrypted_password,
                                                                               passphrase, data["title"])
                            self.show_decrypted_password(data['title'], decrypted_password)
                            delete_button.config(state=tk.NORMAL)
                            break
                except Exception as e:
                    messagebox.showerror("Error", f"Failed to decrypt password: {str(e)}")

        def delete_password():
            selected = selected_password.get()
            if not selected:
                messagebox.showwarning("Warning", "No password selected")
                return
            self.file_manager.delete_password(selected)
            update_password_list()
            messagebox.showinfo("Deleted", f"Password titled '{selected}' has been deleted.")
            delete_button.config(state=tk.DISABLED)

        def update_password_list():
            for widget in frame.winfo_children():
                widget.destroy()

            passwords = self.file_manager.load_passwords()
            if not passwords:
                no_passwords_label = tk.Label(frame, text="No passwords found")
                no_passwords_label.pack(pady=5)
            else:
                for data in passwords:
                    rb = tk.Radiobutton(frame, text=data["title"], variable=selected_password, value=data["title"],
                                        command=update_buttons)
                    rb.pack(anchor="w")

                if passwords:
                    selected_password.set(passwords[0]["title"])
                    update_buttons()

        def update_buttons(*args):
            show_button.config(state=tk.NORMAL if selected_password.get() else tk.DISABLED)
            delete_button.config(state=tk.DISABLED)

        top = Toplevel()
        top.title("Saved Passwords")
        self.center_window(top, 0.4, 0.4)

        selected_password = tk.StringVar()

        canvas = tk.Canvas(top)
        frame = tk.Frame(canvas)
        scrollbar = tk.Scrollbar(top, orient="vertical", command=canvas.yview)
        canvas.configure(yscrollcommand=scrollbar.set)

        scrollbar.pack(side="right", fill="y")
        canvas.pack(side="left", fill="both", expand=True)
        canvas.create_window((0, 0), window=frame, anchor="nw")

        frame.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))

        button_frame = tk.Frame(top)
        button_frame.pack(fill="x", pady=5)

        show_button = tk.Button(button_frame, text="Show Password", command=show_selected_password)
        show_button.pack(side="left", padx=5)

        delete_button = tk.Button(button_frame, text="Delete Password", command=delete_password, state=tk.DISABLED)
        delete_button.pack(side="left", padx=5)

        update_password_list()

        selected_password.trace_add("write", update_buttons)
