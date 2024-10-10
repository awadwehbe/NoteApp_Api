from django.db import models
from django.contrib.auth.models import User
from django.conf import settings
# Create your models here.
# models.py in the notes app

class Note(models.Model):
    # Fields for the note
    title = models.CharField(max_length=100)
    category = models.CharField(max_length=50)
    text = models.TextField()
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="notes")
    #the line above establish a one to many relation 
    
    # Timestamp fields
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.title} by {self.user.email}"
