from django.contrib import admin
from .models import User, Credential

admin.site.register(User)
admin.site.register(Credential)