import os
import pickle
import sqlite3

# VULNERABILITY 1: Hardcoded Secrets
AWS_SECRET_KEY = "AKIAIOSFODNN7EXAMPLEKEY"
DATABASE_PASSWORD = "SuperSecretPassword123!"

def process_user_input(user_data):
    # VULNERABILITY 2: Unsafe Deserialization
    parsed_data = pickle.loads(user_data)
    
    # VULNERABILITY 3: Command Injection
    os.system("ping -c 1 " + parsed_data['host'])

def get_user_record(user_id):
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    # VULNERABILITY 4: SQL Injection
    query = f"SELECT * FROM users WHERE id = '{user_id}'"
    cursor.execute(query)
    return cursor.fetchall()