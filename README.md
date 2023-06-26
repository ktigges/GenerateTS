Program generates a Troubleshoot file and downloads it into the current working directory
You need to have Python3 installed along with the plugins for the modules included

The user ID is hard coded at this time, however the password is not stored in the code, it's stored in 2 files, an encoded password and a key file
You utilize the enclosed encryptpwd.py script to create the 2 files used for the password encryption

You will place the password in the filw pwd.txt
Run the encryptpwd.py file, it will read pwd.txt and create pwdkey.txt and encpass.txt that are used to derrive the password for the admin account

