from django.shortcuts import render
from rest_framework import generics,status
from rest_framework.response import Response
from .models import OTP, User
from .serializers import LoginSerializer, UserRegistrationSerializer
from .serializers import SignUpSerializer,OTPVerificationSerializer
import random
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import RefreshToken, AccessToken
from rest_framework.permissions import AllowAny
from django.contrib.auth import get_user_model
from django.core.exceptions import ObjectDoesNotExist
from django.utils import timezone
from datetime import timedelta
from .serializers import PasswordResetRequestSerializer
#
from api.schemas.user_schemas import signup_request_schema, signup_success_response_schema, error_response_schema
from api.schemas.swagger_utils import generate_swagger_auto_schema
from django.core.mail import send_mail
#
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi

# Create your views here.
class HelloAuthView(generics.GenericAPIView):
    def get(self,request):
        return Response(data={'message':'hello auth'},status=status.HTTP_200_OK)
    
class UserCreateView(generics.GenericAPIView):
    serializer_class=UserRegistrationSerializer
    def post(self,request):
        data=request.data #contains the data sent in the POST request by the client
        serializer=self.serializer_class(data=data) #this line create an instance of our serializer with the data of request to check validity of it 
        if serializer.is_valid():
            serializer.save()
            return Response(data=serializer.data,status=status.HTTP_201_CREATED)
        return Response(data=serializer.errors,status=status.HTTP_400_BAD_REQUEST)
    
        
##########SignUp view ###############################################

class SignUpView(APIView):
    authentication_classes = []  # No authentication required
    permission_classes = [AllowAny]  # Allow any user (even unauthenticated) to access this view

    @generate_swagger_auto_schema(
        operation_summary="User Sign-Up",
        operation_description="Create a new user account by providing email, first name, last name, and password.",
        request_schema=signup_request_schema,
        success_response_schema=signup_success_response_schema,
        error_response_schema=error_response_schema,
        tags=["User Authentication"]
    )

    def post(self, request, *args, **kwargs):
        try:
            serializer = SignUpSerializer(data=request.data)
            
            if serializer.is_valid():
                # Save the user instance
                instance = serializer.save()

                # Generate a random OTP (for testing purposes)
                otp = random.randint(100000, 999999)

                # Store OTP in session (or database if needed)
                # request.session['otp'] = otp #request.session is a dictionary-like object used to store session data for a particular user across requests. 
                # request.session['email'] = instance.email
                otp_instance, created = OTP.objects.get_or_create(user=instance)
                otp_instance.otp = otp
                otp_instance.created_at = timezone.now()
                otp_instance.save()

                #send otp via email
                send_mail(
                    subject="Your OTP for Account Verification",
                    message=f"Your OTP code is {otp}. It will expire in 10 minutes.",
                    from_email=settings.DEFAULT_FROM_EMAIL,
                    recipient_list=[instance.email],  # Send to the user's email
                    fail_silently=False,
                )



                # Successful response
                return Response({
                    "statusCode": 200,
                    "message": "User created successfully",
                    "data": {
                        "firstName": instance.first_name,
                        "lastName": instance.last_name,
                        "email": instance.email,
                        "otp":otp,
                    }
                }, status=status.HTTP_201_CREATED)
            
            # Handle validation errors (e.g., email already exists)
            return Response({
                "statusCode": 400,
                "message": "Email already exists"
            }, status=status.HTTP_400_BAD_REQUEST)

        except Exception as e:
            # Handle unexpected internal server errors
            return Response({
                "statusCode": 500,
                "message": "Internal server error"
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    

#####OTP verification view ###############################################

from rest_framework import status
from django.utils import timezone
from datetime import timedelta

class OTPVerificationView(APIView):
    authentication_classes = []  # No authentication required
    permission_classes = [AllowAny]  # Allow any user (even unauthenticated) to access this view
    @swagger_auto_schema(
        operation_summary="User verification",
        operation_description="Verify your email by requesting using email and otp.",
        request_body=OTPVerificationSerializer,
        responses={
            200: "Email verified successfully",
            400: "Invalid or expired verification code",
            404:"User not found",
            500: "Internal server error"
        }
    )
    def post(self, request, *args, **kwargs):
        serializer = OTPVerificationSerializer(data=request.data)

        if serializer.is_valid():
            email = serializer.validated_data['email']  # Assuming email is provided for OTP lookup
            otp_provided = serializer.validated_data['otp']

            # Get the user and their OTP from the database
            try:
                user = User.objects.get(email=email)
                otp_instance = OTP.objects.get(user=user)

                # Check if OTP matches and hasn't expired
                if otp_instance.otp == otp_provided and not otp_instance.is_expired():
                    # Mark the user as verified
                    user.is_verified = True
                    user.save()

                    # Optionally delete the OTP after successful verification
                    otp_instance.delete()

                    # Generate JWT tokens for the user
                    access_token = AccessToken.for_user(user)
                    refresh_token = RefreshToken.for_user(user)

                    return Response({
                        "statusCode": 200,
                        "message": "Email verified successfully",
                        "data": {
                            "user": {
                                "firstName": user.first_name,
                                "lastName": user.last_name,
                                "email": user.email,
                                "isVerified": True
                            },
                            "accessToken": str(access_token),
                            "refreshToken": str(refresh_token)
                        }
                    }, status=status.HTTP_200_OK)
                else:
                    return Response({
                        "statusCode": 400,
                        "message": "Invalid or expired verification code"
                    }, status=status.HTTP_400_BAD_REQUEST)

            except User.DoesNotExist:
                return Response({
                    "statusCode": 404,
                    "message": "User not found"
                }, status=status.HTTP_404_NOT_FOUND)
            except OTP.DoesNotExist:
                return Response({
                    "statusCode": 400,
                    "message": "OTP not found"
                }, status=status.HTTP_400_BAD_REQUEST)

        return Response({
            "statusCode": 400,
            "message": "Invalid data",
            "errors": serializer.errors
        }, status=status.HTTP_400_BAD_REQUEST)



    
#####request new OTP verification view ###############################################

User = get_user_model()

class PasswordResetRequestView(APIView):
    authentication_classes = []  # No authentication required
    permission_classes = [AllowAny]  # Allow any user (even unauthenticated) to access this view
    @swagger_auto_schema(
        operation_summary="password reset request",
        operation_description="Create a new user account by providing email, first name, last name, and password.",
        request_body=PasswordResetRequestSerializer,
        responses={
            201: "Password reset sent successfully",
            404: "User not found",
            500: "Internal server error"
        }
    )
    def post(self, request, *args, **kwargs):
        serializer = PasswordResetRequestSerializer(data=request.data)

        if not request.data.get('email'):
            return Response({
                "statusCode": 400,
                "message": "Email is required"
            }, status=status.HTTP_400_BAD_REQUEST)

        if serializer.is_valid():
            email = serializer.validated_data['email']

            try:
                # Fetch the user by email
                user = User.objects.get(email=email)

                # Generate a random OTP
                otp = random.randint(100000, 999999)

                # Check if an OTP already exists for the user, if so, update it.
                if hasattr(user, 'otp'):
                    user.otp.otp = otp
                    user.otp.created_at = timezone.now()
                    user.otp.save()
                else:
                    # Create a new OTP record
                    OTP.objects.create(user=user, otp=otp)

                # Here you can send the OTP via email or other methods.
                # For now, we're just returning a success message.
                return Response({
                    "statusCode": 200,
                    "message": "Password reset sent successfully",
                    "otp":otp,
                }, status=status.HTTP_200_OK)

            except ObjectDoesNotExist:
                return Response({
                    "statusCode": 404,
                    "message": "User not found"
                }, status=status.HTTP_404_NOT_FOUND)

        return Response({
            "statusCode": 500,
            "message": "Internal server error"
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

#####login view ###############################################
from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.permissions import AllowAny

class LoginView(APIView):
    permission_classes = [AllowAny]  # Allow any user to access this view

    @swagger_auto_schema(
        operation_summary="password reset request",
        operation_description="Create a new user account by providing email, first name, last name, and password.",
        request_body=LoginSerializer,
        responses={
            200: "Login successful, email verified",
            400: "User not found",
            500: "Internal server error"
        }
    )
    def post(self, request, *args, **kwargs):
        try:
            serializer = LoginSerializer(data=request.data)

            if serializer.is_valid():
                user = serializer.validated_data['user']
                tokens = serializer.get_tokens_for_user(user)

                # Prepare the response data
                response_data = {
                    "statusCode": 200,
                    "message": "Login successful, email verified",
                    "data": {
                        "user": {
                            "firstName": user.first_name or "N/A",  # Use N/A if the name is not present
                            "lastName": user.last_name or "N/A",
                            "email": user.email,
                            "isVerified": user.is_verified,
                        },
                        "accessToken": tokens['access'],
                        "refreshToken": tokens['refresh']
                    }
                }
                return Response(response_data, status=status.HTTP_200_OK)

            # Handle validation errors
            return Response(
                {"statusCode": 400, "message": serializer.errors},
                status=status.HTTP_400_BAD_REQUEST
            )
        except Exception as e:
            # Log the exception (optional)
            print(f"An error occurred: {str(e)}")
            return Response(
                {"statusCode": 500, "message": "Internal server error", "error": str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

##### REQ PASS RESET view ###############################################
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from django.core.mail import send_mail
from django.conf import settings
from django.contrib.auth import get_user_model
from random import randint
from django.utils import timezone
from .serializers import RequestResetPasswordSerializer

User = get_user_model()

class RequestResetPasswordView(APIView):
    permission_classes = [AllowAny]  # Allow any user to access this view

    @swagger_auto_schema(
        operation_summary="User Sign-Up",
        operation_description="Create a new user account by providing email, first name, last name, and password.",
        request_body=RequestResetPasswordSerializer,
        responses={
            200: "password reset send successfully",
            400: "Email is required",
            500: "Internal server error"
        }
    )
    def post(self, request, *args, **kwargs):
        serializer = RequestResetPasswordSerializer(data=request.data)

        if not serializer.is_valid():
            return Response({
                "statusCode": 400,
                "message": "Email is required",
                "errors": serializer.errors
            }, status=status.HTTP_400_BAD_REQUEST)

        try:
            # Get the user by email
            email = serializer.validated_data['email']
            user = User.objects.get(email=email)

            # Generate OTP (handled in the view)
            otp = str(randint(100000, 999999))  # Generate a 6-digit OTP

            # Save OTP and the timestamp in the user model
            user.user_otp = otp
            user.otp_created_at = timezone.now()
            user.save()

            # Send OTP to the user's email
            send_mail(
                subject="Password Reset OTP",
                message=f"Your OTP code is {otp}. It will expire in 10 minutes.",
                from_email=settings.DEFAULT_FROM_EMAIL,
                recipient_list=[user.email],
                fail_silently=False,
             )

            return Response({
                "statusCode": 200,
                "message": "Password reset sent successfully",
                "otp":otp
            }, status=status.HTTP_200_OK)

        except User.DoesNotExist:
            return Response({
                "statusCode": 404,
                "message": "User not found"
            }, status=status.HTTP_404_NOT_FOUND)

        except Exception as e:
            # Log the error (optional)
            print(f"Error occurred during password reset: {str(e)}")
            return Response({
                "statusCode": 500,
                "message": "Internal server error"
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

##### PASS RESET view ###############################################
from django.utils import timezone
from django.contrib.auth.hashers import make_password
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from authentication.models import User, OTP  # Assuming the OTP model is in the authentication app
from .serializers import ResetPasswordConfirmSerializer

from authentication.models import User, OTP  # Assuming this is where OTP is defined

class ResetPasswordConfirmView(APIView):
    permission_classes = [AllowAny]

    @swagger_auto_schema(
        operation_summary="User Sign-Up",
        operation_description="Create a new user account by providing email, first name, last name, and password.",
        request_body=SignUpSerializer,
        responses={
            200: "password reset successfully",
            400: "All fields required",
            500: "Internal server error"
        }
    )
    def post(self, request, *args, **kwargs):
        serializer = ResetPasswordConfirmSerializer(data=request.data)

        if not serializer.is_valid():
            return Response({
                "statusCode": 400,
                "message": "All fields required",
                "errors": serializer.errors
            }, status=status.HTTP_400_BAD_REQUEST)

        email = serializer.validated_data['email']
        code = serializer.validated_data['code']
        new_password = serializer.validated_data['newPassword']

        try:
            # Get the user by email
            user = User.objects.get(email=email)

            # Fetch the OTP from the user's model (assuming user_otp stores the OTP code)
            otp_instance = user.user_otp

            # Check if the OTP matches
            if otp_instance == code:
                # Check if the OTP has expired (assuming otp_created_at stores the timestamp)
                otp_created_at = user.otp_created_at
                if otp_created_at:
                    time_diff = timezone.now() - otp_created_at
                    if time_diff.total_seconds() > 600:  # Expiry time: 10 minutes (600 seconds)
                        return Response({
                            "statusCode": 400,
                            "message": "OTP has expired"
                        }, status=status.HTTP_400_BAD_REQUEST)

                # OTP is valid and not expired, update the user's password
                user.password = make_password(new_password)  # Hash the new password
                user.user_otp = None  # Clear the OTP after successful password reset
                user.save()

                return Response({
                    "statusCode": 200,
                    "message": "Password reset successfully"
                }, status=status.HTTP_200_OK)
            else:
                return Response({
                    "statusCode": 400,
                    "message": "Invalid verification code"
                }, status=status.HTTP_400_BAD_REQUEST)

        except User.DoesNotExist:
            return Response({
                "statusCode": 400,
                "message": "User not found"
            }, status=status.HTTP_400_BAD_REQUEST)

        except Exception as e:
            # Log the error (optional)
            print(f"Error occurred during password reset: {str(e)}")
            return Response({
                "statusCode": 500,
                "message": "Internal server error"
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

################## new otp for reset password 
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import AllowAny
from django.utils import timezone
from random import randint
from .models import User  # Adjust based on your models file
from .serializers import RequestNewPasswordResetSerializer  # Adjust based on your serializers file

class RequestNewPasswordResetView(APIView):
    permission_classes = [AllowAny]  # Allow any user to access this view

    @swagger_auto_schema(
        operation_summary="User Sign-Up",
        operation_description="Create a new user account by providing email, first name, last name, and password.",
        request_body=SignUpSerializer,
        responses={
            200: "A new password reset otp has been sent to your email",
            404: "user not found",
            500: "Internal server error"
        }
    )
    def post(self, request, *args, **kwargs):
        serializer = RequestNewPasswordResetSerializer(data=request.data)

        # Validate the incoming data
        if not serializer.is_valid():
            return Response({
                "statusCode": 400,
                "message": "Email is required",
                "errors": serializer.errors
            }, status=status.HTTP_400_BAD_REQUEST)

        try:
            # Get the user by email
            email = serializer.validated_data['email']
            user = User.objects.get(email=email)

            # Generate a new OTP
            otp = str(randint(100000, 999999))  # Generate a 6-digit OTP

            # Save OTP and the timestamp in the user model
            user.user_otp = otp
            user.otp_created_at = timezone.now()  # Assuming you have this field
            user.save()

            #Send OTP to the user's email
            send_mail(
                subject="New Password Reset OTP",
                message=f"Your new OTP code is {otp}. It will expire in 10 minutes.",
                from_email=settings.DEFAULT_FROM_EMAIL,
                recipient_list=[user.email],
                fail_silently=False,
             )

            return Response({
                "statusCode": 200,
                "message": "A new password reset OTP has been sent to your email.",
                "otp":otp
            }, status=status.HTTP_200_OK)

        except User.DoesNotExist:
            return Response({
                "statusCode": 404,
                "message": "User not found"
            }, status=status.HTTP_404_NOT_FOUND)

        except Exception as e:
            # Log the error (optional)
            print(f"Error occurred while sending new OTP: {str(e)}")
            return Response({
                "statusCode": 500,
                "message": "Internal server error"
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

#######sign out view ###############################
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated  # Require authentication
from django.contrib.auth import logout

class SignOutView(APIView):
    authentication_classes = []  # No authentication required
    permission_classes = [AllowAny]  # Allow any user (even unauthenticated) to access this view

    @swagger_auto_schema(
        operation_summary="User Sign-Up",
        operation_description="Create a new user account by providing email, first name, last name, and password.",
        request_body=SignUpSerializer,
        responses={
            200: "Successfully signed out",
            500: "Internal server error"
        }
    )
    def post(self, request, *args, **kwargs):
        try:
            # Log out the user
            logout(request)

            # Clear the authentication cookies
            response = Response({
                "statusCode": 200,
                "message": "Successfully signed out"
            }, status=status.HTTP_200_OK)

            # Optionally, you can set the cookie expiry to clear it from the client's browser
            response.delete_cookie('sessionid')  # Replace with your actual session cookie name if different
            return response

        except Exception as e:
            # Log the error (optional)
            print(f"Error occurred during sign out: {str(e)}")
            return Response({
                "statusCode": 500,
                "message": "Internal server error"
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

######refresh token view ##########################

from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import AllowAny  # Allow any user
from rest_framework import status
from rest_framework.authentication import get_authorization_header
from django.utils.translation import gettext as _
from rest_framework_simplejwt.tokens import AccessToken, TokenError
from rest_framework_simplejwt.authentication import JWTAuthentication

class RefreshTokenView(APIView):
    permission_classes = [AllowAny]  # You may set this to IsAuthenticated based on your use case

    @swagger_auto_schema(
        operation_summary="User Sign-Up",
        operation_description="Create a new user account by providing email, first name, last name, and password.",
        request_body=SignUpSerializer,
        responses={
            200: "Access token refresh successfully",
            401: "refresh token not",
            500: "Internal server error"
        }
    )
    def post(self, request, *args, **kwargs):
        # Get the Authorization header
        auth = get_authorization_header(request).split()

        if not auth or auth[0].lower() != b'Bearer':
            return Response({
                "statusCode": 401,
                "message": "Refresh token not provided"
            }, status=status.HTTP_401_UNAUTHORIZED)

        if len(auth) == 1:
            return Response({
                "statusCode": 401,
                "message": "Refresh token not provided"
            }, status=status.HTTP_401_UNAUTHORIZED)
        elif len(auth) > 2:
            return Response({
                "statusCode": 401,
                "message": "Invalid token format"
            }, status=status.HTTP_401_UNAUTHORIZED)

        refresh_token = auth[1].decode('utf-8')

        try:
            # Create a new access token from the refresh token
            token = AccessToken.for_user(JWTAuthentication().get_user_from_refresh_token(refresh_token))

            return Response({
                "statusCode": 200,
                "message": "Access token refreshed successfully",
                "data": {
                    "accessToken": str(token)
                }
            }, status=status.HTTP_200_OK)

        except TokenError as e:
            return Response({
                "statusCode": 401,
                "message": str(e)
            }, status=status.HTTP_401_UNAUTHORIZED)
        
        except Exception as e:
            # Log the error (optional)
            print(f"Error occurred during token refresh: {str(e)}")
            return Response({
                "statusCode": 500,
                "message": "Internal server error"
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
