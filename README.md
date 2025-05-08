# Python-Password-Manager
Password Manager 🔐

A secure, customizable and user-friendly desktop application to manage website credentials. Built with Python, CustomTkinter, SQLite, and Fernet encryption, this project focuses on user security, ease of use, and future extensibility.

🎓 Features

User authentication system with secure login

Forgot Password? functionality with email-based reset

Add, retrieve, delete passwords per user

Encrypted password storage using cryptography.Fernet

CustomTkinter modern UI (dark theme, hover effects, smooth transitions)

Logout functionality with return to login screen

🛠️ Technologies Used

Python 3

CustomTkinter for modern UI

SQLite for local user & password storage

cryptography.fernet for symmetric encryption

smtplib, email.mime for email notifications

🔢 Getting Started

Clone this repo

Install dependencies:

pip install cryptography customtkinter

Run the app:

python Password_Manager.py

📧 Email Reset Setup

Update sender credentials in send_email_notification():

sender_email = "youremail@example.com"
sender_password = "your_app_password"

Enable app password or less secure access in your email provider (e.g., Gmail)

✨ Future Improvements

--TBA--

🚀 Screenshots

--Add screenshots in the /assets folder to show UI examples.--

📅 Contributors

Developed by Silvia Grigoras as part of an educational project.

✉️ Feedback

Feel free to submit issues, suggestions or pull requests to help improve the project!
