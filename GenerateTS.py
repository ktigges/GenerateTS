# Author.....: Kevin Tigges
# Script Name: GenerateTS.py
# Desc.......: Script to run a troubleshoot on a device and download using the API calls to the device
#              Yes I should turn the password tools into a module - I will do this later
# 
#
# Last Updates: 5/22/2023
#

import requests
from cryptography.fernet import Fernet
import os
import time
import base64
import os
import argparse
import xml.etree.ElementTree as ET
# Don't print the SSL warnings - as we disabled them.  
# You may change the code to validate the SSL cert if that meets your requirements
from urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)



def get_password():
# Password is encrypted so it is not present in this script and is read from 2 files containing the encrypted password and key
# There is a script called encryptpwd.py that should be used to generate the encrypted password to be used prior to using this script
#
# Place the password in a file called pwd.txt (This will be deleted once the encrypted password is generated)
# Run the script - python3 ./encryptpwd.py
# 2 files will be generated that should be kept in the script directory and will be utilized to authenticate below
#
# read encrypted pwd and convert into byte
#
    cwd = os.getcwd()
    with open(cwd + '/encpass.txt') as f:
        encpwd = ''.join(f.readlines())
        encpwdbyt = bytes(encpwd, 'utf-8')
    f.close()

    # read key and convert into byte
    with open(cwd+ '/pwdkey.txt') as f:
        refKey = ''.join(f.readlines())
        refKeybyt = bytes(refKey, 'utf-8')
    f.close()

    # use the key and decrypt the password

    keytouse = Fernet(refKeybyt)
    # Convert the password from byte to Ascii
    pw = (keytouse.decrypt(encpwdbyt)).decode('ASCII')
    return pw.strip()


def returnheader(user_id, user_password):
# Functions returns the "Authorization Basic" header with the userid:password encoded in base64
#
    authstr = user_id + ":" + user_password
    bytestr = authstr.encode('ascii')
    authb64 = base64.b64encode(bytestr)
    authb64 = str(authb64, encoding='utf-8')

    header = { "Authorization" : "Basic %s" % authb64}
    return(header)
    


def generate_troubleshoot(user_id, user_password, firewall_ip):
# Makes the URL call to generate the TS file
# If the call returns a 200, the job was submitted successfully
#
    url = f"https://{firewall_ip}/api/?type=export&category=tech-support "
    
    response = requests.get(url, headers=returnheader(user_id, user_password), verify=False)

    if response.status_code == 200:
        return str(response.content, 'utf-8')
    else:
        raise Exception("Failed to generate troubleshoot file.")


def getjobid(txtresponse):
# response will have the job ID after the <job> tag
# Loop through the response after the <job> tag until the end tag starts (</job>) grabbing out the job number
#
    i = txtresponse.find('<job>')
    # what position is the <job> string at?
    jobid = ""
    # Start at the position 5 over from the tag
    i = i + 5
    # while the incrementer is less than the total length
    while i < len(txtresponse):
        #if we have hit the end of job tag (<) then break out - we are done
        if (txtresponse[i] == "<"):
            break
        #otherwise add the jobid character to the end result
        else:
            jobid = jobid + txtresponse[i]
        #increment the counter
        i = i + 1
    return(jobid)

def isjobdone(jobid, user_id, user_password, firewall_ip):
# Check if the job is completed
# Job will show "FIN" if it's completed
#
    cmd = '<show><jobs><id>' + jobid + '</id></jobs></show>'
    url = f"https://{firewall_ip}/api/?type=op&cmd={cmd}"
    response= ""
    response = requests.get(url, headers=returnheader(user_id, user_password), verify=False)
    if response.status_code == 200:
        s = str(response.content, 'utf-8')
    else:
        print(f"Failed to get job status... Exiting.....")
        raise SystemExit
    
    if s.find('FIN') > 0:
        return True
    else:
        if s.find('FIN') == -1:
            return False
        else:
            print(f"Failed to get job status - Invalid result returned.... Exiting.....")
            raise SystemExit
    return False

def download_ts(firewall_ip, user_id, user_password, jobid):
# Download the TS file
# Filename will be the firewall IP + _troubleshoot_ + the Job ID
#
    url = f"https://{firewall_ip}/api/?type=export&category=tech-support&action=get&job-id={jobid}"
    response = requests.get(url, headers=returnheader(user_id, user_password), verify=False)
    if response.status_code == 200:
       file_name = f"{firewall_ip}_troubleshoot_{jobid}.tgz"
       with open(file_name, "wb") as f:
           f.write(response.content)
           print(f"Troubleshoot file downloaded: {file_name}")
    else:
        print("Failed to download troubleshoot file.")


def main(firewall_ip):
    user_id = "apiuser"
    user_password = get_password()
    jobid = ""

    try:

       response = generate_troubleshoot(user_id, user_password, firewall_ip)
       jobid = getjobid(response)
       print('Tech Support Queued on ' + firewall_ip + ': Job ID ' + jobid + '\n')
       print('Checking Job Status: ')
       dot = "."
       while not isjobdone(jobid, user_id, user_password, firewall_ip):
           print(dot, end= "", flush=True)
           time.sleep(5)
       print("\n") 
       print(f"Downloading TS file for job:{jobid}")
       download_ts(firewall_ip, user_id, user_password, jobid)
    except Exception as e:
        print(f"Failed to download troubleshoot file  : {str(e)}")

if __name__ == "__main__":
    # Create the Parser for the command line arguments
    p = argparse.ArgumentParser(description="GenerateTS")
    p.add_argument("firewall_ip", type=str, help="Enter the firewall IP")
    args = p.parse_args()
    main(args.firewall_ip)