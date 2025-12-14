#FILE-ENCRYPTION-SYSTEM
# Secure File Storage System

## Description
This project is a secure file storage web application developed using Flask.
It uses hybrid encryption (AES-GCM + RSA) to securely store and retrieve user files.
User authentication is implemented using Flask-Login and password hashing with Bcrypt.

## Features
- User registration and login
- Secure file upload and download
- AES-GCM encryption for files
- RSA encryption for AES keys
- Integrity verification using SHA-256
- Access control (only file owner can download/delete)

## Technologies Used
- Python
- Flask
- Flask-SQLAlchemy
- Flask-Login
- Flask-Bcrypt
- Cryptography
- SQLite

## How to Run
1. Install Python 3.x
2. Install dependencies:
   pip install -r requirements.txt
3. Run the application:
   python app.py
4. Open browser and visit:
   http://127.0.0.1:5000/
