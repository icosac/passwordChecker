from hashlib import sha1
import requests
import re
import sys, os
import argparse

breaches=re.compile(r".+:(?P<breaches>\d+).*")

hashes_path="./hashes.txt"
emails_path="./emails.txt"

hashes=list()
emails=list()

def populate_hashes():
    global hashes
    with open(hashes_path, "r") as f:
        for line in f:
            line=line[:-1]
            if len(line)!=40:
                raise Exception("Line has wrong length {}!=40".format(len(line)))
            hashes.append({"key" : line[:5].upper(), "rest" : line[5:].upper()})

def populate_emails():
    global emails
    with open(emails_path, "r") as f:
        for line in f:
            emails.append(line[:-1])

def hash_password():
    return sha1(password.encode("utf-8")).hexdigest()

def test_password(key, value):
    response=requests.get("https://api.pwnedpasswords.com/range/"+key)
    for line in response.iter_lines():
        if value in str(line):
            ret=breaches.match(str(line)).groupdict()["breaches"]
            return int(ret)
    return 0

def main():
    print("Checking passswords:".upper()) 
    for h in hashes:
        i=hashes.index(h)+1
        print(i, h["key"].upper(), h["rest"].upper())
        ret=test_password(h["key"].upper(), h["rest"].upper())
        if ret>0:
            print("OH NOOOO, password {} breached {} times".format(i, ret))

    print("\nChecking emails: unfortunately no email can be checked since they ask me for money and I already spend too much money on stuff without a proper wage".upper())


def argparser():
    parser=argparse.ArgumentParser(description="Simple script to test whether passwords and/or emails have been leaked. This check is done against Have I been Pwned who I dearly thank for the work they do.")
    parser.add_argument("-e", "--emails", action="store", type=str, help="path to email file")
    parser.add_argument("-x", "--hashes", action="store", type=str, help="path to hash file")
    return parser.parse_args()

if __name__=="__main__":
    args=argparser()

    if args.hashes:
        if os.path.isfile(args.hashes):
            hashes_path=args.hashes
        else:
            raise Exception("Cannot find {}".format(args.hashes))

    if args.emails:
        if os.path.isfile(args.emails):
            emails_path=args.emails
        else:
            raise Exception("Cannot find {}".format(args.emails))

    populate_hashes()
    populate_emails()
    
    main()
