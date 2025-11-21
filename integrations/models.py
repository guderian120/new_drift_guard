from django.db import models

class Environment(models.Model):
    PROVIDER_CHOICES = [
        ('AWS', 'Amazon Web Services'),
        ('GCP', 'Google Cloud Platform'),
        ('Azure', 'Microsoft Azure'),
    ]

    name = models.CharField(max_length=100, help_text="Friendly name for this environment (e.g., Production, Staging)")
    provider = models.CharField(max_length=20, choices=PROVIDER_CHOICES, default='AWS')
    
    # Credentials (In a real app, these should be encrypted using Fernet or similar)
    aws_access_key = models.CharField(max_length=255, blank=True, null=True)
    aws_secret_key = models.CharField(max_length=255, blank=True, null=True)
    
    iac_repo_url = models.URLField(max_length=500, blank=True, null=True, help_text="URL of the Infrastructure as Code repository")
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.name} ({self.provider})"
