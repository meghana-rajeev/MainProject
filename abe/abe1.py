import re
import base64
import os
import hashlib
import boto3
#import sys

from Crypto.Cipher import AES
from Crypto import Random
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

pli = []  # list of P0000 files
oli = []  # list of Temp files
innerkeyli = []
mylines = []
kli = []
keys = []
# symlist = []
d = 0
e = 0
co = 0
n = 10
num = 0
nu = 0

BS = 16
pad = lambda s: s + (BS - len(s) % BS) * chr(BS - len(s) % BS)
# unpad = lambda s: s[0:-s[-1]]
unpad = lambda s: s[:-ord(s[len(s) - 1:])]


class AESCipher:

    def __init__(self, key):
        self.key = hashlib.sha256(key.encode('utf-8')).digest()

    def encrypt(self, raw):
        raw = pad(raw)
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return base64.b64encode(iv + cipher.encrypt(raw.encode('utf-8')))

    def decrypt(self, enc):
        enc = base64.b64decode(enc)
        iv = enc[:16]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return unpad(cipher.decrypt(enc[16:]))


def createList(str1, li1):
    string = str1
    for i in range(1, n + 1):
        if i < 10:
            string = string + str(i) + ".txt"
            li1.append(string)
            # print (string)
            string = str1
        elif i >= 10 & i < 100:
            l = len(str1)
            string = str1[:l - 1]
            string = string + str(i) + ".txt"
            li1.append(string)


def modulo(str):
    global num
    global nu
    if (str[0] == 'P'):
        nu = int(str[1:6])
    elif (str[0] == "T"):
        nu = int(str[4:7])
    else:
        nu = int(str[6:9])
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
                # print(ke)
            else:
                inilist = [m.start() for m in re.finditer(r",", i)]
                if len(inilist) >= num + 1:
                    r1 = inilist[num - 1]
                    r2 = inilist[num]
                    ke = i[r1 + 1:r2]
                    ke = re.sub(r'\W+', '', ke)
                    kli.append(ke)
    print("kli: ", kli)
    myfile.close()
    # innerEnc(input, kli)


def innerEnc(input, kli):
    global d, co, innerkeyli, nu
    innerkeyli = []
    mylines = []
    c = -1

    fk = open("KeyFile.txt", 'a+')

    with open(input, 'r+') as myfile:
        for myline in myfile:  # For each line, stored as myline,
            mylines.append(myline)
    myfile.close()

    for i in mylines:
        c = c + 1
        if i.find("1)") == 0:
            co = c
            break
    # print(c)
    lk = len(kli)
    # print(lk)

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
        # print(x)
        lin = lin + 1
        if lin == (c + j):
            if j == 2:
                rl.append(x)
                j = j + 1
            else:
                # print("val of i:",i)
                # print("current key:" + kli[i])
                password_en = kli[i].encode()  # Convert to type bytes
                salt = os.urandom(16)

                kdf = PBKDF2HMAC(
                    algorithm=hashes.SHA256(),
                    length=32,
                    salt=salt,
                    iterations=100000,
                    backend=default_backend()
                )

                key = base64.urlsafe_b64encode(kdf.derive(password_en))  # Can only use kdf once
                innerkeyli.append(key)
                fk.write(key.decode())
                fk.write(",")
                fernet = Fernet(key)
                # print("value of j=", j)
                data = x.encode()
                encrypted = fernet.encrypt(data)
                enc = encrypted.decode()
                rl.append(enc + '\n')
                j = j + 1

            if j == 4:
                c = c + 5
                j = 0
                i = i + 1

            if (i >= lk):
                # d = d + 1
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
            k = 0
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
            pass_string + password[i]
        pass_string = ''.join(password)
        keys.append(pass_string)
        myfile.close()
        outerEnc(output, pass_string)


def outerEnc(output, pass_string):
    global e
    fk = open("OuterKeyFile.txt", 'a+')
    fk.write(pass_string)
    # fk.write(",")

    cipher = AESCipher(pass_string)
    with open(output, 'r+') as f:
        data = f.read()
    # length = 16 - (len(data) % 16)
    # data += bytes([length]) * length
    encrypted = cipher.encrypt(data)
    output_file = pli[e]
    with open(output_file, 'wb') as f:
        f.write(encrypted)
    e = e + 1
    # f.close()

    fk.write("\n")
    f.close()
    fk.close()


def decryption(file, symlist):
    def outerDec(file, symlist):
        fk = open("OuterKeyFile.txt", "r")
        x = fk.readlines()
        ln = -1
        # print("nu: ", nu)

        num = int(file[1:6])
        for p in x:
            ln += 1
            if ln == (num - 1):
                pass_string = p[:-1]
        print("Outerkey :", pass_string)

        # num = int(file[1:6])
        # pass_string = keys[num - 1]
        cipher = AESCipher(pass_string)
        with open(file, 'r') as f:
            encrypted = f.read()
        decrypted = cipher.decrypt(encrypted)
        #decrypted = decrypted[:-decrypted[-1]]
        k = oli[num - 1]

        with open(k, 'wb') as ouf:
            ouf.write(decrypted)
        ouf.close()
        f.close()
        fk.close()
        innerDec(k, num, symlist)

    def innerDec(file, num, symlist):
        global co, innerkeyli
        innerkeyli = []
        paranum = []
        i = 0
        j = 0
        lin = -1
        ln = -1
        c = co
        co += 1
        modulo(file)
        output = pli[num - 1]

        ft = open(output, 'r+')
        ft.truncate(0)
        ft.close()

        fk = open("KeyFile.txt", "r")
        x = fk.readlines()

        print("nu: ", nu)
        for p in x:
            ln += 1
            if ln == (nu - 1):
                innerkeyli = p.split(",")
        print("Innerkeyli :", innerkeyli)

        f2 = open(output, "wb")
        f1 = open(file, 'rb')
        dat = f1.readlines()

        for pt in dat:
            lin += 1
            if lin == (co + 1):
                line = pt
                for sym in symlist:
                    # if line.find(sym) >= 0:
                    if sym.lower().encode() in line.lower():
                        paranum.append(co - 1)
                        print("Symptom Found! Val of co = ", co)
                co += 5

        co = c
        lin = -1
        for pt1 in dat:
            lin += 1
            if co in paranum:
                if lin == (co + j):
                    print("co: ", co, "j: ", j, "i: ", i)
                    if j == 2:

                        #enc_pt1=pt1.encode()
                        f2.write(pt1)
                        j = j + 1
                    else:
                        j = j + 1
                        fernet = Fernet(innerkeyli[i])
                        dec = fernet.decrypt(pt1)
                        f2.write(dec)
                        i += 1
                    if j == 4:
                        f2.write("\n")
                        co = co + 5
                        j = 0
            else:
                # f2.write("\n")
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
    # d=0
    global e
    # global symlist

    #reload(sys)
    #sys.setdefaultencoding('utf-8')
    #Type = sys.getfilesystemencoding()

    st = "P0000"
    createList(st, pli)
    st = "Temp00"
    createList(st, oli)

    for inp in pli:
        innerKeyGen(inp)
        innerEnc(inp, kli)

    for ff in pli:
        ft = open(ff, 'r+')
        ft.truncate(0)
        ft.close()

    # sys.setdefaultencoding('utf8')

    for oup in oli:
        ipp = pli[e]
        outerKeyGen(oup)
        upload_file(ipp)

    for ff in oli:
        os.remove(ff)

    for ff in pli:
        os.remove(ff)

    symlist = ["cold"]
    file = "P00003.txt"

    download_file(file)
    decryption(file, symlist)

    fk = open('KeyFile.txt', 'r+')
    fk.truncate(0)

    fk = open('OuterKeyFile.txt', 'r+')
    fk.truncate(0)

if __name__ == "__main__":
    main()