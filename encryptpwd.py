# Description: This program will be executed only when we have a new password.
#
# Place the password in a file called pwd.txt
#
# Create a pwd.txt file with the device password (This is only to encrypted the password and will be removed)
# Run this script and it will create 2 files - pwdkey.txt and encpass.txt
# It will then delete the pwd.txt file to keep the password from being exposed
#
# Requires the cryptography library (pip install cryptography)

from cryptography.fernet import Fernet
import os

### 1. read your password file
with open('pwd.txt') as f:
    mypwd = ''.join(f.readlines())

### 2. generate key and write it in a file
key = Fernet.generate_key()
f = open("pwdkey.txt", "wb")
f.write(key)
f.close()

### 3. encrypt the password and write it in a file
refKey = Fernet(key)
mypwdbyt = bytes(mypwd, 'utf-8') # convert into byte
encryptedPWD = refKey.encrypt(mypwdbyt)
f = open("encpass.txt", "wb")
f.write(encryptedPWD)
f.close()
### 4. delete the password file
if os.path.exists("pwd.txt"):
  os.remove("pwd.txt")
else:
  print("File is not available")