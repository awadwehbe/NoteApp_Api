from rest_framework import serializers
from .models import Profile

class ProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = Profile
        # List all the fields you want to include in the serialized data
        fields = ['firstName', 'lastName', 'email']  # 'user' will show the related user info

    # Optional: If you want to display user-specific details like the username or email
    #user = serializers.StringRelatedField()  # This will display the username of the related user


###################update
# user/serializers.py
from rest_framework import serializers
from django.contrib.auth import get_user_model

User = get_user_model()

class UserUpdateSerializer(serializers.ModelSerializer):
    firstName = serializers.CharField(source='first_name', required=True)
    lastName = serializers.CharField(source='last_name', required=True)
    email = serializers.EmailField(required=True)

    class Meta:
        model = User
        fields = ['firstName', 'lastName', 'email']

    def validate_email(self, value):
        # Additional email validation logic can go here (if needed)
        if User.objects.filter(email=value).exists():
            raise serializers.ValidationError("This email is already taken.")
        return value

