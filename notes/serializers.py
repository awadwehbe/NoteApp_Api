from rest_framework import serializers
from .models import Note
from django.conf import settings
#from .models import User
from django.contrib.auth import get_user_model

User = get_user_model()
"""
by setting AUTH_USER_MODEL = 'authentication.User' and using get_user_model(), you're telling Django to always use 
the User model from the authentication app, and get_user_model() dynamically returns that model wherever it's used in
your code.
"""

class UserNotesSerializer(serializers.ModelSerializer):
    title = serializers.CharField(max_length=100)
    category = serializers.CharField(max_length=50)
    text = serializers.CharField() #The field type serializers.TextField() does not exist in DRF (Django REST Framework). 
    #Instead, serializers.CharField() should be used for text.
    #user = serializers.PrimaryKeyRelatedField(queryset=User.objects.all())
    user = serializers.PrimaryKeyRelatedField(read_only=True)  # The user is read-only and will be set in `save()`

    #serializers.ForeignKey() is not a valid field in DRF serializers. Instead, you should use serializers.
    # PrimaryKeyRelatedField() to handle foreign keys.

    class Meta:
        model = Note
        fields = ['id','title', 'category', 'text', 'user']

    # def validate(self, attrs):
    #     user = attrs.get('user')
        
    #     if not user.objects.filter(id=user.id).exists():
    #         raise serializers.ValidationError(detail="User does not exist")
        
    #     return super().validate(attrs)

        
#get Note serializer

class GetNoteSerializer(serializers.ModelSerializer):
    class Meta:
        model=Note
        fields=['id', 'category', 'title', 'text', 'user']
        extra_kwargs={ #This allows you to add extra settings or behavior to specific fields.
            'user': {'read_only': True}  # Make the user read-only

        }