from django.shortcuts import render
from rest_framework import generics,status
from rest_framework.response import Response

# Create your views here.
class HelloUserView(generics.GenericAPIView):
    def get(self,request):
        return Response(data={'message':'hello user'},status=status.HTTP_200_OK)
    
#########
from rest_framework.views import APIView
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from .serializers import ProfileSerializer
from django.shortcuts import get_object_or_404
from django.contrib.auth import get_user_model
from rest_framework_simplejwt.authentication import JWTAuthentication

User = get_user_model()

class GetUserByIdView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request, user_id):
        try:
            # Check for the access token in the request
            if 'HTTP_AUTHORIZATION' not in request.META:
                return Response({
                    "success": False,
                    "message": "No token provided"
                }, status=status.HTTP_401_UNAUTHORIZED)

            # Fetch user by ID
            try:
                user = User.objects.get(id=user_id)
            except User.DoesNotExist:
                return Response({
                    "statusCode": 404,
                    "message": "User not found"
                }, status=status.HTTP_404_NOT_FOUND)

            # Return user data
            return Response({
                "statusCode": 200,
                "message": "User fetched successfully",
                "data": {
                    "user": {
                        "firstName": user.first_name,
                        "lastName": user.last_name,
                        "email": user.email
                    }
                }
            }, status=status.HTTP_200_OK)

        except Exception as e:
            # Handle any internal server errors
            return Response({
                "statusCode": 500,
                "message": "Internal server error"
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

###########################update

# user/views.py
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from rest_framework import status
from django.contrib.auth import get_user_model
from rest_framework_simplejwt.authentication import JWTAuthentication
from .serializers import UserUpdateSerializer

User = get_user_model()

class UpdateUserByIdView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def put(self, request, user_id):
        try:
            # Check for the access token in the request
            if 'HTTP_AUTHORIZATION' not in request.META:
                return Response({
                    "success": False,
                    "message": "No token provided"
                }, status=status.HTTP_401_UNAUTHORIZED)

            # Fetch user by ID
            try:
                user = User.objects.get(id=user_id)
            except User.DoesNotExist:
                return Response({
                    "statusCode": 404,
                    "message": "User not found"
                }, status=status.HTTP_404_NOT_FOUND)

            # Use the serializer for validation and updating
            serializer = UserUpdateSerializer(user, data=request.data)
            if serializer.is_valid():
                serializer.save()

                # Return the updated user data
                return Response({
                    "statusCode": 200,
                    "message": "User updated successfully",
                    "data": {
                        "user": serializer.data
                    }
                }, status=status.HTTP_200_OK)
            else:
                # Handle invalid input data
                return Response({
                    "statusCode": 400,
                    "message": "Invalid input data",
                    "errors": serializer.errors
                }, status=status.HTTP_400_BAD_REQUEST)

        except Exception as e:
            # Handle any internal server errors
            return Response({
                "statusCode": 500,
                "message": "Internal server error"
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
