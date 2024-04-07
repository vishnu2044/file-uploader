from django.db import models
from django.contrib.auth.models import User
# Create your models here.
class UserDetails(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    phone_no = models.CharField(max_length=12, null=True, blank=True)