import os
import csv
import bcrypt

USER_FILE = "users.csv"

def hash_password(password):
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

def verify_password(stored_password, provided_password):
    return bcrypt.checkpw(provided_password.encode(), stored_password.encode())

def register_user(username, password):
    if os.path.exists(USER_FILE):
        with open(USER_FILE, 'r') as file:
            reader = csv.reader(file)
            for row in reader:
                if row[0] == username:
                    return False
    with open(USER_FILE, 'a', newline='') as file:
        writer = csv.writer(file)
        writer.writerow([username, hash_password(password)])
    return True

def authenticate_user(username, password):
    if os.path.exists(USER_FILE):
        with open(USER_FILE, 'r') as file:
            reader = csv.reader(file)
            for row in reader:
                if row[0] == username and verify_password(row[1], password):
                    return True
    return False
