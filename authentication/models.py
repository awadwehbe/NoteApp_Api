from django.db import models
from django.contrib.auth.models import AbstractBaseUser, PermissionsMixin,BaseUserManager
from django.contrib.auth.base_user import BaseUserManager


# Create your models here.
class CustomUserManager(BaseUserManager):

    def create_user(self, email, first_name, last_name, password=None):
        # Ensures email is present
        if not email:
            raise ValueError('Users must have an email address')
        email = self.normalize_email(email)
        user = self.model(email=email, first_name=first_name, last_name=last_name)
        user.set_password(password)
        user.save(using=self._db)
        return user
    def create_superuser(self, email, first_name, last_name, password=None):
        # Create and save superuser
        user = self.create_user(email, first_name, last_name, password)
        user.is_admin = True
        user.is_staff = True
        user.is_superuser = True
        user.save(using=self._db)
        return user

# User Model
class User(AbstractBaseUser, PermissionsMixin):
    # Fields for the User model
    email = models.EmailField(max_length=255, unique=True)
    first_name = models.CharField(max_length=30)
    last_name = models.CharField(max_length=30)
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)
    is_admin = models.BooleanField(default=False)
    is_verified = models.BooleanField(default=True)

     # Add otp and otp expiration
    user_otp = models.CharField(max_length=6, blank=True, null=True)  # You can adjust the length if needed
    otp_created_at = models.DateTimeField(blank=True, null=True)
    
    # Custom manager for User
    objects = CustomUserManager()
    
    # Defines the username field as 'email'
    USERNAME_FIELD = 'email'
    
    # Required fields for creating a user
    REQUIRED_FIELDS = ['first_name', 'last_name']

    def __str__(self):
        return self.email
    

# authentication/models.py

from django.conf import settings
from django.utils import timezone
from datetime import timedelta

class OTP(models.Model):
    user = models.OneToOneField(
        settings.AUTH_USER_MODEL, 
        on_delete=models.CASCADE, 
        related_name='otp'
    )
    otp = models.CharField(max_length=6)  # Store 6-digit OTP
    created_at = models.DateTimeField(auto_now_add=True)
    #verified = models.BooleanField(default=False)  # Track if OTP is verified
    


    def is_expired(self):
        # OTP expires after 10 minutes
        return timezone.now() > self.created_at + timedelta(minutes=10)

    def __str__(self):
        return f"OTP for {self.user.email}: {self.otp}"

######################################################################

