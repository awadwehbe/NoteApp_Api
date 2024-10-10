import ssl
from urllib import request
import certifi
from .models import User
from rest_framework import serializers

import random
from django.core.mail import send_mail
from django.conf import settings
from datetime import timedelta
from django.utils import timezone
from rest_framework import serializers
from .models import User, OTP  # Assuming you have an OTP model linked to the User

class UserRegistrationSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(max_length=255)
    first_name = serializers.CharField(max_length=30)
    last_name = serializers.CharField(max_length=30)
    password = serializers.CharField(min_length=8, write_only=True)

    class Meta:
        model = User
        fields = ['first_name', 'last_name', 'email', 'password']

    def validate(self, attrs):
        email_exists = User.objects.filter(email=attrs['email']).exists()
        if email_exists:
            raise serializers.ValidationError(detail="User with this email already exists")
        
        return super().validate(attrs)

    def create(self, validated_data):
        # Handle password hashing before creating a user
        password = validated_data.pop('password', None)
        instance = self.Meta.model(**validated_data)
        if password is not None:
            instance.set_password(password)  # Hash the password
        instance.save()

        # Generate OTP after user creation
        otp = self.generate_otp()
        self.save_otp(instance, otp)

        # Send OTP to the user’s email
        self.send_otp_email(instance, otp)

        return instance

    def generate_otp(self):
        """Generates a random 6-digit OTP"""
        return str(random.randint(100000, 999999))

    def save_otp(self, user, otp):
        """Save the OTP to the database with an expiration time"""
        OTP.objects.update_or_create(
            user=user,
            defaults={
                'otp': otp,
                'created_at': timezone.now(),
                # Optionally add expiration logic if you want OTP to expire
            }
        )

    # def send_otp_email(self, user, otp):
    #     """Send OTP to user's email"""
    #     subject = 'Your Account Verification OTP'
    #     message = f'Hello {user.first_name},\n\nYour OTP for account verification is {otp}. It will expire in 10 minutes.\n\nThank you!'
    #     email_from = settings.EMAIL_HOST_USER
    #     recipient_list = [user.email] # Send to the user's email address

        
    #      # Send the OTP email using the settings.EMAIL_HOST_USER as the sender
    #     send_mail(subject, message, email_from, recipient_list)

        """
        send_mail(
    subject,          # The subject of the email.
    message,          # The body or content of the email.
    email_from,       # The sender's email address (where the email is coming from).
    recipient_list    # A list of recipients' email addresses.
)

        """

class OTPVerificationSerializer(serializers.Serializer):
    email = serializers.EmailField()
    otp = serializers.CharField(max_length=6)

    def validate(self, data):
        # Validate that the email and OTP exist and are valid
        email = data.get('email')
        otp = data.get('otp')

        try:
            user = User.objects.get(email=email)
            otp_instance = user.otp

            # Check if OTP is correct and not expired
            if otp_instance.otp != otp:
                raise serializers.ValidationError("Invalid OTP.")
            if otp_instance.is_expired():
                raise serializers.ValidationError("OTP has expired.")
            
        except User.DoesNotExist:
            raise serializers.ValidationError("User not found.")
        except OTP.DoesNotExist:
            raise serializers.ValidationError("OTP not found for this user.")

        return data


###########signUp serializer
class SignUpSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True)

    class Meta:
        model = User
        fields = ['email', 'first_name', 'last_name', 'password']

    def create(self, validated_data):
        # Create a new user instance
        user = User(
            email=validated_data['email'],
            first_name=validated_data['first_name'],
            last_name=validated_data['last_name']
        )
        user.set_password(validated_data['password'])  # Hash the password
        user.save()
        return user

    def validate_email(self, value):
        # Check if email already exists
        if User.objects.filter(email=value).exists():
            raise serializers.ValidationError("This email is already in use.")
        return value
    
######## new otp request
class PasswordResetRequestSerializer(serializers.Serializer):
    email = serializers.EmailField()

    def validate_email(self, value):
        """
        Validate that the email exists in the database.
        """
        if not User.objects.filter(email=value).exists():
            raise serializers.ValidationError("User not found")
        return value
    
###login serializer
from django.contrib.auth import authenticate
from rest_framework_simplejwt.tokens import RefreshToken
from .models import User

class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField(required=True)
    password = serializers.CharField(required=True, write_only=True)

    def validate(self, data):
        email = data.get('email')
        password = data.get('password')

        if not email or not password:
            raise serializers.ValidationError("Email and password are required.")

        # Check if the user exists with the given email
        user = User.objects.filter(email=email).first()
        if user is None:
            raise serializers.ValidationError("Invalid credentials.")
        
        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            raise serializers.ValidationError("Invalid credentials.")


        # Authenticate the user using the email as username
        user = authenticate(request, username=email, password=password)

        if user is None:
            raise serializers.ValidationError("Invalid credentials.")

        # Ensure the email is verified
        if hasattr(user, 'otp') and not user.otp.is_verified:
            raise serializers.ValidationError("Email is not verified.")

        data['user'] = user
        return data


    # Add self as the first parameter
    def get_tokens_for_user(self, user):
        refresh = RefreshToken.for_user(user)
        access = refresh.access_token
        return {
            'access': str(access),
            'refresh': str(refresh)
        }

#################RequestResetPasswordSerializer
from rest_framework import serializers
from django.contrib.auth import get_user_model

User = get_user_model()

class RequestResetPasswordSerializer(serializers.Serializer):
    email = serializers.EmailField()

    def validate_email(self, value):
        try:
            user = User.objects.get(email=value)
        except User.DoesNotExist:
            raise serializers.ValidationError("User not found")
        return value

################### PASS RESET serializer###############################################

class ResetPasswordConfirmSerializer(serializers.Serializer):
    email = serializers.EmailField()
    code = serializers.CharField(max_length=6)  # Adjust the length according to your OTP length
    newPassword = serializers.CharField(min_length=8, write_only=True)

    def validate(self, data):
        # Ensure all fields are provided
        if not all([data.get('email'), data.get('code'), data.get('newPassword')]):
            raise serializers.ValidationError("All fields are required.")
        return data
###### new otp for reset password
from rest_framework import serializers

class RequestNewPasswordResetSerializer(serializers.Serializer):
    email = serializers.EmailField(required=True)

#####
