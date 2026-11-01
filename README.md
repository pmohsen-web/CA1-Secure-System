CA1 – Secure System
Student: Pierre Mohsen

Overview
This project demonstrates secure software design principles through a web-based authentication system.

Implemented security controls include:
PBKDF2 password hashing
Account lockout protection
SQLite secure storage
Input validation
Audit logging

Repository Structure:
app_web.py Main application
auth_lockout.py Account lockout logic
passwords_pbkdf2.py Password hashing functions
storage_sqlite.py Database storage
validate_strict.py Input validation
audit_file.py Audit log management

Requirements:
Python 3.11+
pip

Installation:
Clone repository: cd CA1-Secure-System
pip install -r requirements.txt
