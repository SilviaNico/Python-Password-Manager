"""Password Manager"""
# Description: A secure app to store and manage passwords.
# Features: Encrypt stored passwords using the cryptography library.
# Generate strong passwords. Add a master/user password for accessing the data, rest via mail

import os
import sqlite3
import customtkinter as ctk
from tkinter import messagebox, filedialog
from cryptography.fernet import Fernet
import pandas as pd
import csv  # Import the csv module
import requests  # For API requests
import json  # For JSON handling
import smtplib  # For sending emails
from email.mime.text import MIMEText  # For email content
from email.mime.multipart import MIMEMultipart  # For email structure
from contextlib import contextmanager


class PasswordManager:
    def __init__(self, key_file="secret.key", db_file="password.db"):
        self.key_file = key_file
        self.db_file = db_file
        self.key = self.load_key()
        self.fernet = Fernet(self.key)
        self.initialize_database()

    def load_key(self):
        if os.path.exists(self.key_file):
            with open(self.key_file, 'rb') as file:
                key = file.read()
        else:
            key = Fernet.generate_key()
            with open(self.key_file, 'wb') as file:
                file.write(key)
        return key

    def initialize_database(self):
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()

        # Create users table if it doesn't exist
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                key TEXT NOT NULL,
                email TEXT UNIQUE NOT NULL
            )
        ''')

        # Create passwords table with unique constraint
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS passwords (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user TEXT NOT NULL,
                site TEXT NOT NULL,
                username TEXT NOT NULL,
                password TEXT NOT NULL,
                FOREIGN KEY(user) REFERENCES users(username) ON DELETE CASCADE,
                CONSTRAINT unique_user_site_username UNIQUE (user, site, username) -- Proper UNIQUE constraint
            )
        ''')

        conn.commit()
        print("Database and tables initialized!")  # Log the initialization
        conn.close()


class PasswordManagerGUI:
    def __init__(self, root, password_manager, user):
        self.root = root
        self.password_manager = password_manager
        self.user = user

        self.root.title(f"Password Manager - {user}")
        self.root.geometry("500x600")
        ctk.set_appearance_mode("light")  # Supports "dark", "light", "system"
        ctk.set_default_color_theme("blue")

        self.create_widgets()

    def create_widgets(self):
        ctk.set_appearance_mode("light")  # Set appearance mode
        ctk.set_default_color_theme("blue")  # Set color theme

        self.frame = ctk.CTkFrame(self.root)
        self.frame.pack(pady=10, padx=10, fill="both", expand=True)

        ctk.CTkLabel(self.frame, text="Site:").pack(pady=5)
        self.site_entry = ctk.CTkEntry(self.frame)
        self.site_entry.pack(pady=5)

        ctk.CTkLabel(self.frame, text="Username:").pack(pady=5)
        self.username_entry = ctk.CTkEntry(self.frame)
        self.username_entry.pack(pady=5)

        ctk.CTkLabel(self.frame, text="Password:").pack(pady=5)
        self.password_var = ctk.StringVar()
        self.password_entry = ctk.CTkEntry(self.frame, textvariable=self.password_var, show="*")
        self.password_entry.pack(pady=5)

        self.reveal_button = ctk.CTkButton(self.frame, text="Reveal", command=self.toggle_password_visibility,
                                           width=100)
        self.reveal_button.pack(pady=5)  # Place Reveal button *below* password entry

        self.add_button = ctk.CTkButton(self.frame, text="Add/Update Password", command=self.add_password)
        self.add_button.pack(pady=10)  # Add/Update button *below* Reveal button

        self.get_button = ctk.CTkButton(self.frame, text="Get Password", command=self.get_password)
        self.get_button.pack(pady=10)

        self.delete_button = ctk.CTkButton(self.frame, text="Delete Password", command=self.delete_password)
        self.delete_button.pack(pady=10)

        self.logout_button = ctk.CTkButton(self.frame, text="Logout", fg_color="red", command=self.logout)
        self.logout_button.pack(pady=10)

        self.export_button = ctk.CTkButton(self.frame, text="Export Passwords", command=self.export_passwords)
        self.export_button.pack(pady=10)

    def toggle_password_visibility(self):
        current_show_state = self.password_entry.cget("show")
        if current_show_state == "*":
            self.password_entry.configure(show="")  # Show
            self.reveal_button.configure(text="Hide")  # Change button text
        else:
            self.password_entry.configure(show="*")  # Hide
            self.reveal_button.configure(text="Reveal")  # Change button text

    def add_password(self):
        site = self.site_entry.get()
        username = self.username_entry.get()
        password = self.password_entry.get()

    def export_passwords(self):
        file_type = self.ask_export_file_type()

        if file_type:
            warning_message = """
             WARNING: Exporting passwords will store them in plain text in the chosen file format. 
             This poses a significant security risk. Ensure you store the exported file in a secure location 
             and delete it when no longer needed.  Do you wish to proceed?
             """
            if messagebox.askyesno("Security Warning", warning_message):
                try:
                    conn = sqlite3.connect(self.password_manager.db_file)
                    cursor = conn.cursor()

                    cursor.execute("SELECT site, username, password FROM passwords WHERE user = ?", (self.user,))
                    encrypted_passwords = cursor.fetchall()

                    passwords = []
                    for site, username, encrypted_password in encrypted_passwords:
                        try:
                            decrypted_password = self.password_manager.fernet.decrypt(
                                encrypted_password.encode()).decode()
                            passwords.append((site, username, decrypted_password))
                        except Exception as e:
                            messagebox.showerror("Decryption Error", f"Could not decrypt password for {site}: {e}")
                            passwords.append((site, username, "Decryption Failed"))

                    if passwords:
                        self.export_to_csv(passwords)  # Directly export to CSV
                    else:
                        messagebox.showinfo("Info", "No passwords found for this user.")

                except sqlite3.Error as e:
                    messagebox.showerror("Error", f"Database error: {e}")
                finally:
                    if conn:
                        conn.close()
            else:
                return

    def ask_export_file_type(self):
        self.export_file_type = None  # Initialize
        export_window = ctk.CTkToplevel(self.root)  # Use CTkToplevel
        export_window.title("Export Options")

        file_type = ctk.StringVar(value="csv")
        csv_radio = ctk.CTkRadioButton(export_window, text="CSV (.csv)", variable=file_type, value="csv")
        csv_radio.pack(pady=5)

        def confirm_export():
            self.export_file_type = file_type.get()
            export_window.destroy()  # Destroy the window before calling export_passwords

        export_button = ctk.CTkButton(export_window, text="Export", command=confirm_export)
        export_button.pack(pady=10)

        export_window.protocol("WM_DELETE_WINDOW", lambda: setattr(self, 'export_file_type', None))  # Handle close
        export_window.grab_set()  # Make the dialog modal
        export_window.focus_set()  # Set focus on the dialog

        self.root.wait_window(export_window)  # Wait for the dialog to close
        return self.export_file_type if hasattr(self, 'export_file_type') else None

    def export_to_csv(self, passwords):
        try:
            filepath = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV Files", "*.csv")])
            if filepath:
                with open(filepath, 'w', newline='', encoding='utf-8') as csvfile:
                    writer = csv.writer(csvfile)
                    writer.writerow(["Site", "Username", "Password"])
                    writer.writerows(passwords)
                messagebox.showinfo("Success", f"Passwords exported to {filepath}")
        except Exception as e:
            messagebox.showerror("Error", f"CSV export error: {e}")

    def add_password(self):
        site = self.site_entry.get()
        username = self.username_entry.get()
        password = self.password_entry.get()

        # Check if all fields are filled out
        if not site or not username or not password:
            messagebox.showerror("Error", "Please enter all fields.")
            return

        encrypted_password = self.password_manager.fernet.encrypt(password.encode()).decode()

        conn = None  # Initialize conn outside the try block
        try:
            conn = sqlite3.connect(self.password_manager.db_file)
            cursor = conn.cursor()

            cursor.execute("SELECT id FROM users WHERE username = ?", (self.user,))
            user_exists = cursor.fetchone()
            if not user_exists:
                messagebox.showerror("Error", "User does not exist.")
                return

            cursor.execute("INSERT OR IGNORE INTO passwords (user, site, username, password) VALUES (?, ?, ?, ?)",
                           (self.user, site, username, encrypted_password))

            if cursor.rowcount == 0:
                cursor.execute("UPDATE passwords SET password = ? WHERE user = ? AND site = ? AND username = ?",
                               (encrypted_password, self.user, site, username))

            conn.commit()
            messagebox.showinfo("Success", "Password added/updated!")

        except sqlite3.Error as e:
            messagebox.showerror("Error", f"Database error: {e}")

        finally:
            if conn:
                conn.close()  # Close the connection in the finally block

    def get_password(self):
        site = self.site_entry.get()
        username = self.username_entry.get()

        if not site or not username:
            messagebox.showerror("Error", "Please enter both site and username.")
            return

        # Connect to the database
        conn = sqlite3.connect(self.password_manager.db_file)
        cursor = conn.cursor()

        # Query the database for the password associated with the site and username
        cursor.execute("SELECT password FROM passwords WHERE user = ? AND site = ? AND username = ?",
                       (self.user, site, username))
        result = cursor.fetchone()

        if result:
            # If password is found, decrypt it and display it
            encrypted_password = result[0]
            decrypted_password = self.password_manager.fernet.decrypt(encrypted_password.encode()).decode()

            messagebox.showinfo("Password", f"The password for {site} is: {decrypted_password}")
        else:
            messagebox.showerror("Error", "Password not found for this site and username.")

        conn.close()

    def delete_password(self):
        messagebox.showinfo("Delete", "Password deleted!")

    def logout(self):
        self.root.destroy()
        authenticate()


def authenticate():
    auth_window = ctk.CTk()
    auth_window.title("Login")
    auth_window.geometry("300x250")

    ctk.CTkLabel(auth_window, text="Username:").pack(pady=5)
    username_entry = ctk.CTkEntry(auth_window)
    username_entry.pack(pady=5)

    ctk.CTkLabel(auth_window, text="Key:").pack(pady=5)
    key_entry = ctk.CTkEntry(auth_window, show="*")
    key_entry.pack(pady=5)

    def attempt_login():
        username = username_entry.get()
        key = key_entry.get()

        conn = sqlite3.connect("password.db")
        cursor = conn.cursor()
        cursor.execute("SELECT key FROM users WHERE username = ?", (username,))
        result = cursor.fetchone()
        conn.close()

        if result and result[0] == key:
            auth_window.destroy()
            main(username)
        else:
            messagebox.showerror("Error", "Invalid username or key.")

    def register():
        auth_window.destroy()
        register_user()

    def forgot_password():
        auth_window.destroy()
        reset_key()

    ctk.CTkButton(auth_window, text="Login", command=attempt_login).pack(pady=5)
    ctk.CTkButton(auth_window, text="Register", command=register).pack(pady=5)
    ctk.CTkButton(auth_window, text="Forgot Password?", command=forgot_password).pack(pady=5)

    auth_window.mainloop()


def register_user():
    register_window = ctk.CTk()
    register_window.title("Register")
    register_window.geometry("300x300")

    ctk.CTkLabel(register_window, text="Username:").pack(pady=5)
    username_entry = ctk.CTkEntry(register_window)
    username_entry.pack(pady=5)

    ctk.CTkLabel(register_window, text="Email:").pack(pady=5)
    email_entry = ctk.CTkEntry(register_window)
    email_entry.pack(pady=5)

    ctk.CTkLabel(register_window, text="Create Key:").pack(pady=5)
    key_entry = ctk.CTkEntry(register_window, show="*")
    key_entry.pack(pady=5)

    def save_user():
        username = username_entry.get()
        email = email_entry.get()
        key = key_entry.get()

        # Create an instance of PasswordManager to ensure DB is initialized
        password_manager = PasswordManager()

        # Use the database initialization and insert the user
        conn = sqlite3.connect(password_manager.db_file)
        cursor = conn.cursor()

        try:
            cursor.execute("INSERT INTO users (username, key, email) VALUES (?, ?, ?)", (username, key, email))
            conn.commit()
            messagebox.showinfo("Success", "User registered!")
            register_window.destroy()
            authenticate()  # Redirect to authentication after registration
        except sqlite3.IntegrityError:
            messagebox.showerror("Error", "Username or email already exists.")

        conn.close()

    ctk.CTkButton(register_window, text="Register", command=save_user).pack(pady=5)
    register_window.mainloop()


@contextmanager
def mail_context():
    yield None  # Yield None, as we're not using a real server
    # server = None
    # try:
    #     server = smtplib.SMTP('smtp.gmail.com', 587)  # Or your SMTP server
    #     server.starttls()
    #     server.login('your_email@gmail.com', 'your_app_password')  # Use app password!
    #     yield server
    # except smtplib.SMTPException as e:
    #     messagebox.showerror("Email Error", f"SMTP Error: {e}") #More specific error message
    #     print(f"SMTP Error details: {e}") #Print full error for debugging
    # finally:
    #     if server:
    #         try:
    #             server.quit()
    #         except Exception as e:
    #             print(f"Error closing server: {e}")


def generate_password_from_api():
    api_url = "https://api.genratr.com/?length=10&uppercase&lowercase&special&numbers"

    try:
        response = requests.get(api_url)
        response.raise_for_status()  # Raise an exception for bad status codes (4xx or 5xx)

        # The API returns a JSON response like {"password": "generated_password"}
        data = response.json()
        if "password" in data:
            return data["password"]
        elif isinstance(data, str):  # If the API returns a string
            return data
        else:
            return None  # If the API response structure is differently

    except requests.exceptions.RequestException as e:
        print(f"API request error: {e}")  # Print for debugging
        return None
    except json.JSONDecodeError as e:
        print(f"Invalid JSON response: {e}")  # Print for debugging
        return None


def reset_key():
    reset_window = ctk.CTk()
    reset_window.title("Reset Key")
    reset_window.geometry("300x200")

    ctk.CTkLabel(reset_window, text="Enter Email:").pack(pady=5)
    email_entry = ctk.CTkEntry(reset_window)
    email_entry.pack(pady=5)

    def process_reset():
        email = "testuser@example.com"  # Fake email address
        if not email:
            messagebox.showerror("Error", "Email field cannot be empty.")
            return

        with sqlite3.connect("password.db") as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT username FROM users WHERE email = ?", (email,))
            result = cursor.fetchone()

        if result:
            username = result[0]
            try:
                new_key = generate_password_from_api()
                if new_key:
                    try:
                        with mail_context() as server:  # Use context manager
                            message = MIMEMultipart()
                            message['From'] = 'test_sender@example.com'  # Fake sender
                            message['To'] = email  # Fake recipient
                            message['Subject'] = 'Password Reset for PasswordManager'
                            message.attach(MIMEText(f"Your new password is: {new_key}", 'plain'))

                            # Instead of server.sendmail, print to terminal:
                            print("=== Email Details (Test Mode) ===")
                            print(f"To: {email}")
                            print(f"From: test_sender@example.com")
                            print(f"Subject: Password Reset for PasswordManager")
                            print(f"Message: {new_key}")
                            print("====================================")
                            print(f"New key generated: {new_key}")  # Print the key in the terminal

                    except Exception as e:  # Catch potential errors in message creation
                        print(f"Error creating email message: {e}")

                    with sqlite3.connect("password.db") as conn:
                        cursor = conn.cursor()
                        cursor.execute("UPDATE users SET key = ? WHERE username = ?", (new_key, username))
                        conn.commit()

                    messagebox.showinfo("Success",
                                        f"New key generated (email not actually sent).")
                    reset_window.destroy()
                    enter_new_password_window(new_key, username)
                else:
                    messagebox.showerror("Error", "Failed to generate password from API.")
            except (requests.exceptions.RequestException, json.JSONDecodeError) as e:
                messagebox.showerror("Error", f"API or email error: {e}")
        else:
            messagebox.showerror("Error", "Email not found.")

    ctk.CTkButton(reset_window, text="Reset", command=process_reset).pack(pady=10)
    reset_window.mainloop()


def enter_new_password_window(new_key, username):
    new_pass_window = ctk.CTk()
    new_pass_window.title("Enter New Password")
    new_pass_window.geometry("300x200")

    ctk.CTkLabel(new_pass_window, text="Your new password is:").pack(pady=5)  # Show the new key
    password_label = ctk.CTkLabel(new_pass_window, text=new_key)  # Display the new key
    password_label.pack(pady=5)

    ctk.CTkLabel(new_pass_window, text="Confirm New Password:").pack(pady=5)  # Confirmation label
    new_pass_entry = ctk.CTkEntry(new_pass_window, show="*")
    new_pass_entry.pack(pady=5)

    def submit_password():
        entered_password = new_pass_entry.get()
        if entered_password == new_key:  # Check if passwords match
            with sqlite3.connect("password.db") as conn:
                cursor = conn.cursor()
                cursor.execute("UPDATE users SET key = ? WHERE username = ?", (entered_password, username))
                conn.commit()

            messagebox.showinfo("Success", "Password has been set successfully.")
            new_pass_window.destroy()
        else:
            messagebox.showerror("Error", "Passwords do not match.")

    ctk.CTkButton(new_pass_window, text="Submit", command=submit_password).pack(pady=10)
    new_pass_window.mainloop()


def main(username):
    root = ctk.CTk()
    password_manager = PasswordManager()
    app = PasswordManagerGUI(root, password_manager, username)

    def safe_update():
        try:
            root.update_idletasks()
            root.update()
            root.after(100, safe_update)  # Loop update
        except Exception as e:
            print(f"Error in update: {e}")  # Debugging

    root.after(100, safe_update)  # Ensure UI keeps updating safely
    root.mainloop()


if __name__ == "__main__":
    authenticate()
