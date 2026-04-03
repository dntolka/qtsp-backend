from django.db import models


class User(models.Model):
    user_hash = models.CharField(max_length=100, unique=True)
    given_name = models.CharField(max_length=100)
    surname = models.CharField(max_length=100)
    issuing_country = models.CharField(max_length=10)

    def __str__(self):
        return self.user_hash


class Credential(models.Model):
    credential_id = models.CharField(max_length=100, unique=True)
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="credentials")
    key_algorithm = models.CharField(max_length=50, default="ECDSA")
    curve = models.CharField(max_length=50, default="P-256")
    is_valid = models.BooleanField(default=True)
    private_key_pem = models.TextField()

    def __str__(self):
        return self.credential_id