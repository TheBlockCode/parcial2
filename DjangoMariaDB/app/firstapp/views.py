# Create your views here.
#IMPORT models
from .models import Movie,ApiUsers
from django.forms.models import model_to_dict

#IMPORT LIBRARIRES/FUNCTIONS
#from django.shortcuts import render , HttpResponse
from django.http import JsonResponse
import json
from firstapp.customClasses import *
#IMPORT DJANGO PASSWORD HASH GENERATOR AND COMPARE
from django.contrib.auth.hashers import make_password, check_password

#check_password(noHashPassword,HashedPassword) this funcion validate if the password match to the hash

def showList(request):
	#VALIDATE METHOD
	if request.method == 'GET':
		#DECLARE RESPONSE
		responseData = {}

		#CHECK JSON STRUCTURE
		isJson = checkJson()
		isJsonResult = isJson.isJson(request.body)

		if (type(isJsonResult) == type(True)):
			jsonBody = json.loads(request.body)
			#CHECK JSON CONTENT
			if 'user' not in jsonBody:
				responseData['result'] = 'error'
				responseData['message'] = 'user is required'
				return JsonResponse(responseData, status=401)

			if 'password' not in jsonBody:
				responseData['result'] = 'error'
				responseData['message'] = 'password is required'
				return JsonResponse(responseData, status=401)

			#CHECK IF USER EXITST
			if (ApiUsers.objects.get(user=jsonBody['user']) != None):
				#TAKE PASSWORD OF THE USER
				user = ApiUsers.objects.get(user=jsonBody['user'])

				#CHECK IF PASSWORD IS CORRECT
				if check_password(jsonBody['password'], user.password):
					#CHECK IF USER HAS API-KEy
					if ApiKey().check(request) == True:
						if user.api_key == request.headers["user-api-key"]:
							#pelis= Movie.objects.all()
							count = 0
							#RETURN RESPONSE
							responseData['result'] = 'success'
							responseData['message'] = 'Valid Credentials'
							responseData['movies'] = {}

							for i in Movie.objects.all():
								responseData["movies"][count]={}
								responseData["movies"][count]['id']= i.movieid
								responseData["movies"][count]['title']= i.movietitle
								responseData["movies"][count]['releaseDate']= i.releasedate
								responseData["movies"][count]['imageurl']= i.imageurl
								count = count + 1
							return JsonResponse(responseData,status=200)
						else:
							responseData['result'] = 'error'
							responseData['message'] = 'Api key incorrecto'
							return JsonResponse(responseData, status=401)

					else:
						responseData['result'] = 'error'
						responseData['message'] = 'se requiere api key'
						return JsonResponse(responseData, status=401)


				else:
                    			responseData['result'] = 'error'
                    			responseData['message'] = 'The user does not exist or the password is incorrect'
                    			return JsonResponse(responseData, status=401)

			else:
				responseData['result'] = 'error'
				responseData['message'] = 'The user does not exist or the password is incorrect'
				return JsonResponse(responseData, status=401)

		else:
			return isJsonResult

	else:
		responseData = {}
		responseData['result'] = 'error'
		responseData['message'] = 'Invalid Request'
		return JsonResponse(responseData, status=400)

def login(request):

	#VALIDATE METHOD
	if request.method == 'POST':
		#DECLARE RESPONSE
		responseData = {}

		#CHECK JSON STRUCTURE
		isJson = checkJson()
		isJsonResult = isJson.isJson(request.body)

		if (type(isJsonResult) == type(True)):
			jsonBody = json.loads(request.body)
			#CHECK JSON CONTENT
			if 'user' not in jsonBody:
				responseData['result'] = 'error'
				responseData['message'] = 'user is required'
				return JsonResponse(responseData, status=401)

			if 'password' not in jsonBody:
				responseData['result'] = 'error'
				responseData['message'] = 'password is required'
				return JsonResponse(responseData, status=401)

			#CHECK IF USER EXITST
			if (ApiUsers.objects.get(user=jsonBody['user']) != None):
				#TAKE PASSWORD OF THE USER
				user = ApiUsers.objects.get(user=jsonBody['user'])

				#CHECK IF PASSWORD IS CORRECT
				if check_password(jsonBody['password'], user.password):
					#CHECK IF USER HAS API-KEY
					if user.api_key == None:
						user.api_key = ApiKey().generate_key_complex()
						user.save()
					#RETURN RESPONSE
					responseData['result'] = 'success'
					responseData['message'] = 'Valid Credentials'
					responseData['userApiKey'] = user.api_key
					return JsonResponse(responseData, status=200)

				else:
                    			responseData['result'] = 'error'
                    			responseData['message'] = 'The user does not exist or the password is incorrect'
                    			return JsonResponse(responseData, status=401)

			else:
				responseData['result'] = 'error'
				responseData['message'] = 'The user does not exist or the password is incorrect'
				return JsonResponse(responseData, status=401)

		else:
			return isJsonResult

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
