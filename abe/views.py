from django.http import HttpResponseRedirect
from django.shortcuts import render
from django.contrib.auth import authenticate, login, logout
from abe.abe1 import decryption

import re
import base64
import os
import hashlib
import boto3
import botocore

from django.contrib.auth.decorators import login_required
# Create your views here.

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

        data = open("./media/"+pid+".txt", 'wb')
        try:
            bucket.download_fileobj(pid+".txt", data)
        except:
            data.close()
            return render(request, 'result.html', {'ans': "file not found"})
        decryption("./media/"+pid+".txt",symptom)

        data.close()


        print(patientid, symptom)
        return render(request, 'result.html', {'ans': patientid + " " + symptom})
    return render(request, 'result.html', {})

