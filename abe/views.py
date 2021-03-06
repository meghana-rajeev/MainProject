import sys

from django.http import HttpResponseRedirect
from django.shortcuts import render
from django.contrib.auth import authenticate, login, logout
from abe.sample3 import decryption
import time

import boto3
import botocore


def home_page(request):

    logout(request)
    if request.POST:
        username = request.POST['drid']
        password = request.POST['psw']

        user = authenticate(username=username, password=password)
        if user is not None:
            if user.is_active:
                login(request, user)
                print(username, password)
                return HttpResponseRedirect('/search')
        else:
            return render(request, "login.html", {'error': True})
    return render(request, "login.html", {})


def searchpage(request):
    return render(request, "medex.html", {})


def result(request):
    if request.POST:
        patientid = request.POST['pid']
        symptom = request.POST['sym']
        pid = patientid
    # s3 = boto3.resource('s3')
     #   try:
     #       s3.Bucket('abemedicalrecords').download_file( KEY,'patientid')
     #   except botocore.exceptions.ClientError as e:
     #       if e.response['Error']['Code'] == "404":
     #           print("The object does not exist.")
     #       else:
     #           raise
        s3 = boto3.resource('s3')
        bucket = s3.Bucket('abemedicalrecords')

        data = open(".\\abe\\"+pid+".txt", 'wb')
        try:
            bucket.download_fileobj(pid+".txt", data)
            time.sleep(5)
            print(pid+" downloaded successfully")
        except:
            data.close()
            return render(request, 'result.html', {'ans': "file not found"})
        #exec(open('decryption.py).read())
        data.close()
        decryption(".\\abe\\"+pid+".txt",symptom)
        #decryption(".\media\\"+pid+".txt",symptom)

        #data.close()

        print(patientid, symptom)

        return render(request, 'result.html', {'ans': patientid + " with " + symptom})
        #return render(request, 'result.html', {'ans': patientid })
    return render(request, 'result.html', {})

