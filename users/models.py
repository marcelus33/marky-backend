from django.contrib.auth.models import AbstractUser
from django.db import models


class User(AbstractUser):
    # email = models.EmailField(unique=True)
    business_name = models.CharField(max_length=255)
    phone_number = models.CharField(max_length=15, blank=True)
    is_verified = models.BooleanField(default=False)
    date_joined = models.DateTimeField(auto_now_add=True)
    # google_id = models.CharField('Google ID', max_length=64, blank=True, null=True)
    # google_token = models.TextField('Google Token', blank=True, null=True)

    # USERNAME_FIELD = 'email'
    # REQUIRED_FIELDS = ['business_name', 'phone_number']

    def __str__(self):
        return self.business_name
