#############
# models.py
from django.db import models
from django.contrib.auth.models import User
from django.conf import settings

from django.db import models

from django.db.models.signals import post_save

from django.dispatch import receiver


# user/models.py
from django.db import models


class Profile(models.Model):
    # Link this profile to the User model from the authentication app
    user = models.OneToOneField(
        settings.AUTH_USER_MODEL, 
        on_delete=models.CASCADE, 
        related_name='profile'
    )

    # Additional fields for the user's profile information
    first_name = models.CharField(max_length=50)
    last_name = models.CharField(max_length=50)
    email = models.EmailField()

    def __str__(self):
        return f"Profile of {self.user.email}"

    @property
    def is_verified(self):
        """
        Ensure the profile's user is verified.
        """
        return self.user.is_verified
# user/signals.py


    @receiver(post_save, sender=settings.AUTH_USER_MODEL)
    def create_user_profile(sender, instance, created, **kwargs):
            if created:
                Profile.objects.create(
                user=instance,
                first_name=instance.first_name,
                last_name=instance.last_name,
                email=instance.email
            )

    @receiver(post_save, sender=settings.AUTH_USER_MODEL)
    def save_user_profile(sender, instance, **kwargs):
        instance.profile.save()

