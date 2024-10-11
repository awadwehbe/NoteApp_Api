
############sign up
from drf_yasg import openapi

# Define the SignUp Request Schema
signup_request_schema = openapi.Schema(
    type=openapi.TYPE_OBJECT,
    required=["email", "password", "firstName", "lastName"],
    properties={
        'email': openapi.Schema(type=openapi.TYPE_STRING, description='User email address'),
        'password': openapi.Schema(type=openapi.TYPE_STRING, description='Password (min 8 characters)'),
        'firstName': openapi.Schema(type=openapi.TYPE_STRING, description='First name'),
        'lastName': openapi.Schema(type=openapi.TYPE_STRING, description='Last name'),
    },
    example={
        "firstName": "John",
        "lastName": "Doe",
        "email": "john.doe@example.com",
        "password": "password123"
    }
)

# Define the SignUp Success Response Schema
signup_success_response_schema = openapi.Response(
    description="User created successfully",
    examples={
        "application/json": {
            "statusCode": 201,
            "message": "User created successfully",
            "data": {
                "firstName": "John",
                "lastName": "Doe",
                "email": "john.doe@example.com",
                "otp": 123456
            }
        }
    },
    schema=openapi.Schema(
        type=openapi.TYPE_OBJECT,
        properties={
            'statusCode': openapi.Schema(type=openapi.TYPE_INTEGER, description="HTTP status code"),
            'message': openapi.Schema(type=openapi.TYPE_STRING, description="Response message"),
            'data': openapi.Schema(
                type=openapi.TYPE_OBJECT,
                properties={
                    'firstName': openapi.Schema(type=openapi.TYPE_STRING, description="User's first name"),
                    'lastName': openapi.Schema(type=openapi.TYPE_STRING, description="User's last name"),
                    'email': openapi.Schema(type=openapi.TYPE_STRING, description="User's email"),
                    'otp': openapi.Schema(type=openapi.TYPE_INTEGER, description="Generated OTP for verification")
                }
            )
        }
    )
)

# Define the Error Response Schema
error_response_schema = openapi.Response(
    description="Validation error",
    examples={
        "application/json": {
            "statusCode": 400,
            "message": "Email already exists",
        }
    },
    schema=openapi.Schema(
        type=openapi.TYPE_OBJECT,
        properties={
            'statusCode': openapi.Schema(type=openapi.TYPE_INTEGER, description="HTTP status code"),
            'message': openapi.Schema(type=openapi.TYPE_STRING, description="Error message"),
        }
    )
)


