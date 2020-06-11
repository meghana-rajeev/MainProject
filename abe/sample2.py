#!/usr/bin/python
import re
import base64
import os
import hashlib
import boto3
import sys

from Crypto.Cipher import AES
from Crypto import Random
from Crypto.Protocol.KDF import PBKDF2
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import importlib

pli = []  # list of P0000 files
oli = []  # list of Temp files
innerkeyli = []
mylines = []
kli = []
keys = []
d = 0
e = 0
co = 0
cou = 0
num = 0
nu = 0
n = 1
iv = "                "


def createList(str1, li1):
    string = str1
    for i in range(1, n + 1):
        if i < 10:
            string = string + str(i) + ".txt"
            li1.append(string)
            string = str1
        elif i >= 10 & i < 100:
            l = len(str1)
            string = str1[:l - 1]
            string = string + str(i) + ".txt"
            li1.append(string)


def modulo(str1):
    global num
    global nu
    if str1[0] == 'P':
        nu = int(str1[1:6])
    elif str1[0] == "T":
        nu = int(str1[4:7])
    else:
        nu = int(str1[6:9])
    num = nu % 3


def innerKeyGen(input):
    global kli, num
    kli = []
    mylines = []

    modulo(input)

    with open(input, 'r+') as myfile:
        for myline in myfile:  # For each line, stored as myline,
            mylines.append(myline)

    for i in mylines:
        k = i.find("Symptom")
        if k == 0:
            if num == 0:
                start = ":"
                end = ","
                ke = i[i.find(start) + len(start):i.find(end)]
                ke = re.sub(r'\W+', '', ke)
                kli.append(ke)
            else:
                inilist = [m.start() for m in re.finditer(r",", i)]
                if len(inilist) >= num + 1:
                    r1 = inilist[num - 1]
                    r2 = inilist[num]
                    ke = i[r1 + 1:r2]
                    ke = re.sub(r'\W+', '', ke)
                    kli.append(ke)
    print(("Inner key list: ", kli))
    myfile.close()


def innerEnc(input, kli):
    global d, co, innerkeyli, nu, cou
    innerkeyli = []
    mylines = []
    c = -1

    fk = open("InnerKeyFile.txt", 'a+')

    with open(input, 'r+') as myfile:
        for myline in myfile:  # For each line, stored as myline,
            mylines.append(myline)
    myfile.close()

    for i in mylines:
        c = c + 1
        if i.find("1)") == 0:
            co = c
            cou = c
            break
    lk = len(kli)

    myfile = open(input, "r+")
    r = myfile.readlines()

    rl = []
    i = 0
    j = 0
    m = 0
    lin = -1

    modulo(input)
    output = oli[nu - 1]

    f = open(output, "w+")

    for x in r:
        lin = lin + 1
        if lin == (c + j):
            if j == 2:
                rl.append(x)
                j = j + 1
            else:
                backend = default_backend()
                salt = os.urandom(16)

                kdf = PBKDF2HMAC(
                    algorithm=hashes.SHA256(),
                    length=32,
                    salt=salt,
                    iterations=100000,
                    backend=backend
                )
                key = base64.urlsafe_b64encode(kdf.derive(kli[i].encode('utf-8')))
                innerkeyli.append(key)
                fk.write(key.decode('utf-8'))
                fk.write(",")
                fernet = Fernet(key)
                data = x.encode('utf-8')
                encrypted = fernet.encrypt(data)
                enc = encrypted.decode('utf-8')
                print("Inner Encryption: " + enc)
                rl.append(enc + '\n')
                j = j + 1

            if j == 4:
                c = c + 5
                j = 0
                i = i + 1

            if i >= lk:
                break

        else:
            rl.append(x)

    f.writelines(rl)
    fk.write("\n")
    f.close()
    fk.close()


def outerKeyGen(output):
    mylines = []
    with open(output, 'r+') as myfile:
        for myline in myfile:  # For each line, stored as myline,
            mylines.append(myline)

        password = []
        pass_string = " "

        k = mylines[2].find(":")  # PatientID
        for i in range(k + 2, k + 8):
            password.append(mylines[2][i])

        k = mylines[3].find(":") + 2  # First Name
        password.append(mylines[3][k])

        k = mylines[5].find(":") + 2  # Last Name
        password.append(mylines[5][k])

        k = mylines[7].find(":")  # DOB
        for i in range(k + 2, k + 12):
            password.append(mylines[7][i])

        password.remove('/')
        password.remove('/')

        for i in range(0, 16):
            pass_string = pass_string + password[i]

        pass_string = ''.join(password)
        print(("Outer key: " + pass_string))
        keys.append(pass_string)

    myfile.close()
    outerEnc(output, pass_string)


BS = 16
pad = lambda s: s + (BS - len(s) % BS) * chr(BS - len(s) % BS)
unpad = lambda s: s[:-ord(s[len(s) - 1:])]


class AESCipher:
    def make_key(password, salt=None):
        if salt is None:
            # Generate a key from the password
            salt = Random.new().read(8)
        key = PBKDF2(password, salt, AES.block_size, 100000)
        return (key, salt)

    def encrypt(message, key):
        # The IV should always be random
        global iv
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(key, AES.MODE_CFB, iv)
        ciphertext = cipher.encrypt(message.encode("utf-8"))
        return (ciphertext, iv)

    def decrypt(ciphertext, key, iv):
        cipher = AES.new(key, AES.MODE_CFB, iv.encode())
        msg = cipher.decrypt(ciphertext).decode("latin-1")
        return msg


def outerEnc(output, pass_string):
    global e, iv, salt
    fk = open("OuterKeyFile.txt", 'a+')
    fk.write(pass_string)

    output_file = pli[e]

    with open(output, 'r+') as f:
        data = f.read()
    print("Encrypted file: " + data)
    key, salt = AESCipher.make_key(pass_string)
    encrypted, iv = AESCipher.encrypt(data, key)
    print(("Outer Encryption: " + encrypted.decode("latin-1")))
    f.close()
    f = open(output_file, "wb")
    f.write(encrypted)

    e = e + 1

    fk.write("\n")
    f.close()
    fk.close()


def decryption(file, symlist):
    def outerDec(file, symlist):
        print("Inside Outer Decryption")
        global salt, iv
        ln = -1
        num = int(file[9:14])
        num1 = int(file[11:14])
        k = "Temp" + str(num1) + ".txt"
        # k = oli[num - 1]
        pass_str = []

        fk = open("./abe/OuterKeyFile.txt", "r")
        x = fk.readlines()

        for p in x:
            ln += 1
            if ln == (num - 1):
                pass_str = p[:-1]

        print(("Outerkey :", pass_str))
        with open(file, 'rb') as f:
            encrypted = f.read()
        # salt and iv must be stored somewhere
        # encrypted=encrypted.decode("latin-1")
        salt = os.urandom(16)
        print("Encrypted: " + encrypted.decode("latin-1"))
        key, _ = AESCipher.make_key(pass_str, salt)
        decrypted = AESCipher.decrypt(encrypted, key, iv)
        print(("Outer Decrypted: " + decrypted))

        with open(k, 'wb') as ouf:
            ouf.write(decrypted.encode("utf-8"))

        ouf.close()
        f.close()
        fk.close()
        innerDec(k, num, symlist)

    def innerDec(file, num, symlist):
        global co, innerkeyli, cou
        co = cou
        innerkeyli = []
        paranum = []
        i = 0
        j = 0
        lin = -1
        ln = -1
        c = co
        co += 1
        # modulo(file)
        num1 = int(file[4:5])
        output = ".\media\P0000" + str(num1) + ".txt"
        # output = pli[num - 1]

        ft = open(output, 'r+')
        ft.truncate(0)
        ft.close()

        fk = open(".\\abe\InnerKeyFile.txt", "r")

        x = fk.readlines()

        print(("nu: ", nu))
        for p in x:
            ln += 1
            if ln == (nu - 1):
                innerkeyli = p.split(",")
        print(("Innerkeyli :", innerkeyli))

        f2 = open(output, "wb")
        f1 = open(file, 'rb')
        dat = f1.readlines()
        print("Inside Inner Decryption:")

        for pt in dat:
            print(pt)
            lin += 1
            if lin == (co + 1):
                line = pt.decode("utf-8")
                print("line: " + line)
                for sym in symlist:
                    if sym.lower() in line.lower():
                        paranum.append(co)
                        print(("Symptom Found! at line ", co))
                co += 5

        co = c + 1
        lin = 0
        for pt1 in dat:
            # pt1=pt1.decode("utf-8")
            lin += 1
            if co in paranum:
                if lin == (co + j):
                    if j == 2:
                        f2.write(pt1)
                        j = j + 1
                    else:
                        j = j + 1
                        fernet = Fernet(innerkeyli[i])
                        dec = fernet.decrypt(pt1)
                        print("Inner decrypted: " + dec.decode("utf-8"))
                        f2.write(dec)
                        i += 1
                    if j == 4:
                        f2.write(b'\n')
                        co = co + 5
                        j = 0
            else:
                co += 5
                i += 3

    outerDec(file, symlist)


def upload_file(file):
    s3 = boto3.client('s3')
    s3.upload_file(file, 'abemedicalrecords', file)


def download_file(file):
    s3 = boto3.client('s3')
    s3.download_file('abemedicalrecords', file, file)


def main():
    global e

    # importlib.reload(sys)
    #    sys.setdefaultencoding('utf-8')

    st = "P0000"
    createList(st, pli)
    st = "Temp00"
    createList(st, oli)

    for inp in pli:  # Inner Encryption
        innerKeyGen(inp)
        innerEnc(inp, kli)
        # print(("Inner Encryption using Fernet is done on "+inp))

    for ff in pli:  # Clearing P0000 files
        ft = open(ff, 'r+')
        ft.truncate(0)
        ft.close()

    for oup in oli:  # Outer Encryption and upload
        ipp = pli[e]
        outerKeyGen(oup)
        # print(("Outer Encryption using AES 256 is done on "+ipp))
        upload_file(ipp)
        # print((ipp+" was uploaded successfully!"))

    for ff in oli:  # Removing Temp00 Files
        os.remove(ff)

    for ff in pli:  # Removing P0000 Files
        os.remove(ff)

        # while True:                 # Download and Decryption
        # fil = str(input("Enter the record name: "))
        fil = fil + ".txt"
        # st = str(input("Enter the symptom list: "))
        symlist = st.split(",")
        # for l in symlist:
        # print(("Symlist: " + l))
        download_file(fil)
        decryption(fil, symlist)
        # ch = int(input("Enter 1 to continue: "))
        # if ch != 1:
        # break

    # fk = open('InnerKeyFile.txt', 'r+')
    # fk.truncate(0)

    # fk = open('OuterKeyFile.txt', 'r+')
    # fk.truncate(0)


if __name__ == "__main__":
    main()
