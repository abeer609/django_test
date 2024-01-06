from django.db import models
from namegen.namegen import generate_username
from django.contrib.auth.models import AbstractUser


class User(AbstractUser):
    username = models.CharField(default=generate_username, unique=True, max_length=50)
    email = models.EmailField()
    is_active = models.BooleanField("active", default=False)
    is_admin = models.BooleanField(default=False)
    otp = models.CharField(max_length=6, blank=True, null=True)
    otp_created = models.DateTimeField(auto_now=True)


class File(models.Model):
    file = models.FileField(upload_to="files")
    owner = models.ForeignKey(User, on_delete=models.CASCADE)
    created_at = models.DateField(auto_now_add=True)
