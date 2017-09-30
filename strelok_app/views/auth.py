from django.shortcuts import render, redirect
from django.http import HttpResponse, JsonResponse
from django.contrib import messages
from django.contrib.auth import logout

def logout_view(request):
    logout(request)
    return redirect("/")
