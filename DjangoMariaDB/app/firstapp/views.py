# Create your views here.
#IMPORT models
from .models import Movie,ApiUsers

#IMPORT LIBRARIRES/FUNCTIONS
#from django.shortcuts import render , HttpResponse
from django.http import JsonResponse
import json
from firstapp.customClasses import *
#IMPORT DJANGO PASSWORD HASH GENERATOR AND COMPARE
from django.contrib.auth.hashers import make_password, check_password

#check_password(noHashPassword,HashedPassword) this funcion validate if the password match to the hash

def login(request):

	#VALIDATE METHOD
	if request.method == 'POST':

		#DECLARE RESPONS
		if checkJson().isJson(request.body)==True:
			response_data={}
			json_data = json.loads(request.body)
			attr_error = False
			attrErrorMsg = ""
			if 'usuario' not in json_data:
				attr_error = True
				attrErrorMsg = "Llene el campo"
			elif 'contraseña' not in json_data:
				attr_error = True
				attrErrorMsg="Llene el campo"
			if attr_error == True:
			
				response_data['result'] = 'error'
				response_data['message'] = attrErrorMsg
				return JsonResponse(response_data, status=401)
			else:
				response_data['result'] = 'success'
				response_data['message'] = 'Correcto'
				return JsonResponse(response_data, status=200)

	else:
		responseData = {}
		responseData['result'] = 'error'
		responseData['message'] = 'Invalid Request'
		return JsonResponse(responseData, status=400)


def makepassword(request,password):
    hashPassword = make_password(password)
    response_data = {}
    response_data['password'] = hashPassword
    return JsonResponse(response_data, status=200)
