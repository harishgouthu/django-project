from django.shortcuts import redirect,render
from django.http import HttpResponse
from django.contrib.auth.models import User
from django.contrib import messages
from django.contrib.auth import authenticate,login,logout
from harishproject import settings
from django.core.mail import EmailMessage, send_mail
from django.contrib.sites.shortcuts import get_current_site
from django.template.loader import render_to_string
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.utils.encoding import force_bytes,force_str
from django.contrib.auth import authenticate, login, logout
from . tokens import generate_token


# Create your views here.

def home(request):
    return render(request,'authentication/index.html')
    #return HttpResponse('<i><h1>hi this is harish</h1></i>')
def display(request):
    return render(request,'authentication/display.html')

def signup(request):
    if request.method =='POST':
        username=request.POST['username']
        fname=request.POST['fname']
        lname=request.POST['lname']
        email=request.POST['email']
        pass1=request.POST['pass1']
        pass2=request.POST['pass2']
        
        if User.objects.filter(username=username):
            messages.error(request, 'username is already exist! Please try another')
            return redirect('home')
        if User.objects.filter(email=email):
            messages.error(request, 'email is already exist! Please try another')
            return redirect('home')
        if len(username)>10:
            messages.error(request, 'username must be under 10 characters')
            return redirect('home')        
        if pass1 != pass2:
            messages.error(request, 'password did not match! Please try again')
            return redirect('home') 
        if not username.isalnum():
            messages.error(request, 'username must be alpha-numeric!')
            return redirect('home') 
                 
        myuser=User.objects.create_user(username=username, email=email, password=pass1)
        myuser.first_name=fname
        myuser.last_name=lname
        # myuser.is_active = False
        myuser.is_active = False
        myuser.save()
        messages.success(request, "your account created successfully. we have sent an confirmation email in order to activate your account.")
        
        #welcome to email
        
        subject = "Welcome to django.core."
        message = "hello" + myuser.first_name + myuser.last_name + "!!\n" + "welcome to django!!\n thanking you for visiting our website\n we have sent  a confirmation email,please confirm eamil in order to activate your account.\n\n Thanking you\nHarish kumar" 
        from_email = settings.EMAIL_HOST_USER
        to_list = [myuser.email]
        send_mail(subject,message,from_email,to_list,fail_silently= True)
        
         
        # Email Address Confirmation Email
        current_site = get_current_site(request)
        email_subject = "Confirm your Email @ GFG - Django Login!!"
        message2 = render_to_string('email_confirmation.html',{
            
            'name': myuser.first_name,
            'domain': current_site.domain,
            'uid': urlsafe_base64_encode(force_bytes(myuser.pk)),
            'token': generate_token.make_token(myuser)
        })
        email = EmailMessage(
        email_subject,
        message2,
        settings.EMAIL_HOST_USER,
        [myuser.email],
        )
        email.fail_silently = True
        email.send()
        
        
        return redirect('signin')
    return render(request,'authentication/signup.html')


def activate(request,uidb64,token):
    try:
        uid = force_str(urlsafe_base64_decode(uidb64))
        myuser = User.objects.get(pk=uid)
    except (TypeError,ValueError,OverflowError,User.DoesNotExist):
        myuser = None

    if myuser is not None and generate_token.check_token(myuser,token):
        myuser.is_active = True
        # user.profile.signup_confirmation = True
        myuser.save()
        login(request,myuser)
        messages.success(request, "Your Account has been activated!!")
        return redirect('signin')
    else:
        return render(request,'activation_failed.html')

def signin(request):
    if request.method == 'POST':
        username=request.POST['username']
        pass1=request.POST['pass1']
        user=authenticate(username=username,password=pass1)
        if user is not None:
            login(request,user)
            fname=user.first_name
            lname=user.last_name
            data ={'fname':fname,'lname':lname}
            messages.success(request,'you have successfully signin')
            return render(request,'authentication/web.html',data)
        else:
           messages.error(request,'you have entered invalid credentials')
    return render(request,'authentication/signin.html')

def signout(request):
    logout(request)
    messages.info(request,'signout successfully')
    return redirect('home')
