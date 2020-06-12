import re
import base64
import os
import boto3

from Crypto.Cipher import AES
from Crypto import Random
from Crypto.Protocol.KDF import PBKDF2
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


innerkeyli = []
mylines = []
keys = []
kli = []
pli = []  # list of P0000 files
oli = []  # list of Temp files
cou = 0
num = 0
co = 0
nu = 0
d = 0
e = 0
n = 5
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
                #print("Inner Encryption: " + enc)
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
    print("Inner Encryption done on "+input)
    f.writelines(rl)
    fk.write("\n")
    f.close()
    fk.close()


def outerKeyGen(output):
    mylines = []
    with open(output, 'r+') as myfile:
        for myline in myfile:
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


class AESCipher:
    def make_key(password, salt=None):
        if salt is None:
            salt = Random.new().read(8)

        key = PBKDF2(password, salt, AES.block_size, 100000)
        return (key, salt)

    #global iv
    #iv = Random.new().read(AES.block_size)
    def encrypt(message, key):
        global iv
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(key, AES.MODE_CFB, iv)
        ciphertext = cipher.encrypt(message.encode("utf-8"))
        return (ciphertext, iv)

    def decrypt(ciphertext, key, iv):
        cipher = AES.new(key, AES.MODE_CFB, iv)
        msg = cipher.decrypt(ciphertext).decode("latin-1")
        return msg


def outerEnc(output, pass_string):
    global e, iv, salt

    fk = open("OuterKeyFile.txt", 'a+')
    fk.write(pass_string)
    fk.write("\n")
    fk.close()

    output_file = pli[e]

    with open(output, 'r+') as fz:
        data = fz.read()
    #print("Encrypted file: " + data)

    key, salt = AESCipher.make_key(pass_string)

    f11 = open("AESFile.txt", 'ab')
    print("Key: " + key.decode("latin-1"))
    #print(repr(key))
    #print(type(key))
    f11.write(key)
    f11.write(b",")
    print("Salt: " + salt.decode("latin-1"))
    #print(repr(salt))
    f11.write(salt)
    f11.write(b",")
    encrypted, iv = AESCipher.encrypt(data, key)
    print("iv: " + iv.decode("latin-1"))
    #print(repr(iv))
    f11.write(iv)
    f11.write(b"\n")
    f11.close()
    #print(("Outer Encryption: " + encrypted.decode("latin-1")))
    print("Outer Encryption done on "+output_file)
    f = open(output_file, "wb")
    f.write(encrypted)
    e = e + 1
    f.close()


def decryption(file, symlist):
    def outerDec(file, symlist):
        print("Inside Outer Decryption")

        num = int(file[7:12])
        iv = "                "
        pass_str = []

        f1 = open(".\\abe\AESFile.txt", 'rb')
        cont = f1.readlines()
        f1.close()

        li = cont[num - 1].split(b",")

        key = li[0]
        print("key1: " + key.decode('latin-1'))
        print(repr(key))

        salt = li[1]
        print("salt1:" + salt.decode('latin-1'))
        print(repr(salt))

        iv = li[2]
        iv = iv[:16]
        print("iv1:" + iv.decode("latin-1"))
        print(repr(iv))

        ln = -1
        if (num < 10):
            k = ".\\abe\Temp00" + str(num) + ".txt"
        else:
            k = ".\\abe\Temp0" + str(num) + ".txt"

        f2 = open(".\\abe\OuterKeyFile.txt", "r")
        x = f2.readlines()
        f2.close()

        for p in x:
            ln += 1
            if ln == (num - 1):
                pass_str = p[:-1]

        print("Outerkey :", pass_str)
        print("filename: " + file)

        try:
            fk = open(file, 'rb')
            print("Inside Try ", fk.readlines())
            fk.close()
        except Exception as e:
            print("File can't be opened", e)

        with open(file, 'rb') as f3:
            encrypted = f3.read()

        print("Encrypted: " + encrypted.decode("latin-1"))
        decrypted = AESCipher.decrypt(encrypted, key, iv)
        print(("Outer Decrypted: " + decrypted))

        with open(k, 'wb') as f4:
            f4.write(decrypted.encode("utf-8"))

        innerDec(k, num, symlist)

    def innerDec(file, num, symp):
        print("Inside Inner Decryption:")
        co = 0
        cou = -1
        innerkeyli = []
        paranum = []
        symlist=symp.split(",")
        with open(file, 'r+') as myfile:
            for myline in myfile:
                mylines.append(myline)

        for i in mylines:
            cou = cou + 1
            if i.find("Consultations") == 0:
                co = cou + 1
                break
        c = co
        co += 1

        print("file: " + file)
        if (num < 10):
            output = ".\\abe\P0000" + str(num) + ".txt"
        else:
            output = ".\\abe\P000" + str(num) + ".txt"
        print("output: " + output)

        f5 = open(".\\abe\InnerKeyFile.txt", "r")
        x = f5.readlines()
        f5.close()

        i = 0
        j = 0
        lin = -1
        ln = -1

        for p in x:
            ln += 1
            if ln == (num - 1):
                innerkeyli = p.split(",")

        print(("Innerkey :", innerkeyli[num-1]))

        f6 = open(file, 'rb')
        dat = f6.readlines()
        f6.close()

        for pt in dat:
            print(pt)
            lin += 1
            if lin == (co + 1):
                line = pt.decode("utf-8")
                print("line: " + line)
                for sym in symlist:
                    if sym.lower() in line.lower():
                        paranum.append(co)
                        print("Symptom: "+sym)
                        print("line: "+line)
                        print(("Symptom Found! at line ", co))
                co += 5

        f7 = open(output, "wb")
        co = c + 1
        lin = 0
        for pt1 in dat:
            lin += 1
            if co in paranum:
                if lin == (co + j):
                    if j == 2:
                        f7.write(pt1)
                        j = j + 1
                    else:
                        j = j + 1
                        fernet = Fernet(innerkeyli[i])
                        dec = fernet.decrypt(pt1)
                        print("Inner decrypted: " + dec.decode("utf-8"))
                        f7.write(dec)
                        i += 1
                    if j == 4:
                        f7.write(b'\n')
                        co = co + 5
                        j = 0
            else:
                co += 5
                i += 3
        f7.close()

    outerDec(file, symlist)


def upload_file(file):
    s3 = boto3.client('s3')
    s3.upload_file(file, 'abemedicalrecords', file)


def download_file(file):
    s3 = boto3.client('s3')
    s3.download_file('abemedicalrecords', file, file)


def main():
    global e

    st = "P0000"
    createList(st, pli)
    st = "Temp00"
    createList(st, oli)

    kfli=["AESFile.txt","InnerKeyFile.txt","OuterKeyFile.txt"]

    for ff in kfli:  # Clearing P0000 files
        #print(ff + " was cleared!")
        ft = open(ff, 'r+')
        ft.truncate(0)
        ft.close()

    for inp in pli:  # Inner Encryption
        innerKeyGen(inp)
        innerEnc(inp, kli)
        # print(("Inner Encryption using Fernet is done on "+inp))

    for ff in pli:  # Clearing P0000 files
        #print(ff + " was cleared!")
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


if __name__ == "__main__":
    main()