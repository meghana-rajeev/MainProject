from django.http import HttpResponseRedirect
from django.shortcuts import render
from django.contrib.auth import authenticate, login, logout
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
            return render(request, "doctor login.htm", {'error': True})
    return render(request, "doctor login.htm", {})


def searchpage(request):
    return render(request, "demo.html", {})


def result(request):
    if request.POST:
        patientid = request.POST['pid']
        symptom = request.POST['sym']
        print(patientid, symptom)
        return render(request, 'result.html', {'ans': patientid + " " + symptom})
    return render(request, 'result.html', {})

