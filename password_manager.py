import os
import csv
import secrets
from encryption_utils import encrypt_data, decrypt_data

DATA_FILE = "data.csv"

def save_password(title, password, url, other_info, master_key):
    encrypted_password = encrypt_data(master_key, password)
    with open(DATA_FILE, 'a', newline='') as file:
        writer = csv.writer(file)
        writer.writerow([title, encrypted_password, url, other_info])

def search_password(title, master_key):
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, 'r') as file:
            reader = csv.reader(file)
            for row in reader:
                if row[0] == title:
                    decrypted_password = decrypt_data(master_key, row[1])
                    return row[0], decrypted_password, row[2], row[3]
    return None

def update_password(title, new_password, master_key):
    updated = False
    if os.path.exists(DATA_FILE):
        temp_file = DATA_FILE + ".tmp"
        with open(DATA_FILE, 'r') as file, open(temp_file, 'w', newline='') as temp:
            reader = csv.reader(file)
            writer = csv.writer(temp)
            for row in reader:
                if row[0] == title:
                    row[1] = encrypt_data(master_key, new_password)
                    updated = True
                writer.writerow(row)
        os.replace(temp_file, DATA_FILE)
    return updated

def delete_password(title):
    deleted = False
    if os.path.exists(DATA_FILE):
        temp_file = DATA_FILE + ".tmp"
        with open(DATA_FILE, 'r') as file, open(temp_file, 'w', newline='') as temp:
            reader = csv.reader(file)
            writer = csv.writer(temp)
            for row in reader:
                if row[0] != title:
                    writer.writerow(row)
                else:
                    deleted = True
        os.replace(temp_file, DATA_FILE)
    return deleted

def generate_random_password(length=16):
    alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+"
    return ''.join(secrets.choice(alphabet) for _ in range(length))
