from django.shortcuts import render, redirect
from django.contrib.auth.models import User
from django.contrib.auth import authenticate, logout
from .models import UserDetails
from django.contrib import messages
from django.http import JsonResponse, HttpResponseRedirect
import jwt
from django.conf import settings
import re


def generate_jwt_token(user):
    payload = {
        'user_id': user.id,
        'username': user.username,
    }
    token = jwt.encode(payload, settings.SECRET_KEY, algorithm='HS256')
    return {'token': token}  # Return token in a dictionary format

def login(request):

    if request.method == "POST":
        email = request.POST.get('email')
        password = request.POST.get('password')
        
        if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
            return JsonResponse({'message': 'Invalid email format'}, status=400)

        user = User.objects.filter(email=email).first()
        if user:
            user = authenticate(username=user.username, password=password)
            
            if user:
                token = generate_jwt_token(user)    
                return JsonResponse(token, status=200)  
            else:
                return JsonResponse({'message': 'Invalid email or password'}, status=401)
        else:
            return JsonResponse({'message': 'User does not exist'}, status=404)

    return render(request, 'login.html')

def validate_token(request):
    if request.method == "POST":
        token = request.POST.get('token')
        if token:
            user = validate_jwt_token(token)
            if user:
                return JsonResponse({'message': 'Token is valid'}, status=200)
            else:
                return JsonResponse({'message': 'Invalid token'}, status=401)
        else:
            return JsonResponse({'message': 'Token not provided'}, status=400)
    return JsonResponse({'message': 'Invalid request'}, status=400)


def validate_jwt_token(token):
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])
        user_id = payload['user_id']
        user = User.objects.get(id=user_id)
        return user
    except jwt.ExpiredSignatureError:
        return None
    except (jwt.InvalidTokenError, User.DoesNotExist):
        return None



from django.http import JsonResponse
from django.shortcuts import render

def profile(request):
    print("this is working:::::::::::::::::")
    token = request.headers.get('Authorization')
    if token and token.startswith('Bearer '):
        token = token.split(' ')[1]
        user = validate_jwt_token(token)
        if user:
            print(user.username)
            print(user.email)
            full_name = f"{user.first_name} {user.last_name}"
            context = {
                'username': user.username,
                'fullname': full_name,
                'email': user.email
            }
            print(":::::::::::::::::::::::::::::::::::::::::::::::")
            print(context)
            print(":::::::::::::::::::::::::::::::::::::::::::::::")
            return render(request, 'profile.html', context)
        else:
            # Handle case where user is not authenticated
            print("Authentcation not success :::::::::::::::")
            print("Authentcation not success :::::::::::::::")
            return render(request, 'profile.html', {'error_message': 'User authentication failed'})
    else:
        print("token not get ::::::::::::::::::::::::::::::::::::")
        print("token not get ::::::::::::::::::::::::::::::::::::")
        # Handle case where token is missing or in invalid format
        return render(request, 'profile.html', {'error_message': 'Token missing or invalid'})


        


def signup(request):

    if request.method == "POST":
        username = request.POST.get('username')
        email = request.POST.get('email')
        first_name = request.POST.get('first_name')
        last_name = request.POST.get('last_name')
        password = request.POST.get('password')
        phoneno = request.POST.get('phoneno')
        
        if not all([username, email, first_name, last_name, password, phoneno]):
            return JsonResponse({'message': 'Please fill in all the fields.'}, status=400)
        
        if User.objects.filter(username=username).exists():
            return JsonResponse({'message': 'Username already exists.'}, status=400)
            
        user = User.objects.create_user(
            username=username,
            email=email,
            first_name=first_name,
            last_name=last_name,
            password=password
        )
        UserDetails.objects.create(user=user, phone_no=phoneno)
        
        messages.success(request, 'Account created successfully. Please login.')
        return JsonResponse({'redirect': '/login'})
    
    return render(request, 'signup.html')


def user_logout(request):
    try:
        print("function si calling::::::::::::::::::")
        if request.user.is_authenticated:
            logout(request)
            return redirect('login')
        else:
            messages.error(request, 'You need to login first')
            return redirect('login')
    except:
        return redirect('login')