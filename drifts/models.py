from django.db import models
from django.utils import timezone

class DriftEvent(models.Model):
    SEVERITY_CHOICES = [
        ('low', 'Low'),
        ('medium', 'Medium'),
        ('high', 'High'),
        ('critical', 'Critical'),
    ]
    
    STATUS_CHOICES = [
        ('active', 'Active'),
        ('remediated', 'Remediated'),
        ('ignored', 'Ignored'),
    ]
    
    CHANGE_METHOD_CHOICES = [
        ('console', 'AWS/GCP/Azure Console'),
        ('cli', 'Command Line Interface'),
        ('api', 'Direct API Call'),
        ('sdk', 'SDK/Boto3'),
        ('terraform', 'Terraform'),
        ('cloudformation', 'CloudFormation'),
        ('ansible', 'Ansible'),
        ('manual', 'Manual Change'),
        ('unknown', 'Unknown'),
    ]
    
    ROOT_CAUSE_CHOICES = [
        ('manual_change', 'Manual Change via Console/CLI'),
        ('automation_failure', 'Automation/IaC Failure'),
        ('emergency_fix', 'Emergency Hotfix'),
        ('testing', 'Testing/Experimentation'),
        ('misconfiguration', 'Misconfiguration'),
        ('unauthorized', 'Unauthorized Change'),
        ('unknown', 'Unknown'),
    ]

    # Basic drift information
    resource_name = models.CharField(max_length=255)
    resource_type = models.CharField(max_length=100)
    cloud_provider = models.CharField(max_length=50)  # AWS, GCP, Azure
    severity = models.CharField(max_length=20, choices=SEVERITY_CHOICES, default='medium')
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='active')
    detected_at = models.DateTimeField(default=timezone.now)
    description = models.TextField()
    expected_state = models.JSONField(default=dict)
    actual_state = models.JSONField(default=dict)
    
    # Forensic Information - Who
    initiated_by_user = models.CharField(
        max_length=255, 
        blank=True, 
        null=True,
        help_text="Username or IAM user who made the change"
    )
    initiated_by_role = models.CharField(
        max_length=255, 
        blank=True, 
        null=True,
        help_text="IAM role or service account used"
    )
    initiated_by_email = models.EmailField(
        blank=True, 
        null=True,
        help_text="Email of the user who made the change"
    )
    
    # Forensic Information - When
    change_timestamp = models.DateTimeField(
        blank=True, 
        null=True,
        help_text="When the change was actually made"
    )
    
    # Forensic Information - How
    change_method = models.CharField(
        max_length=50, 
        choices=CHANGE_METHOD_CHOICES,
        blank=True, 
        null=True,
        help_text="How the change was made"
    )
    source_ip = models.GenericIPAddressField(
        blank=True, 
        null=True,
        help_text="IP address from which the change was made"
    )
    user_agent = models.TextField(
        blank=True, 
        null=True,
        help_text="User agent string from the request"
    )
    
    # Forensic Information - What
    api_calls = models.JSONField(
        default=list,
        help_text="List of API calls that caused the drift"
    )
    change_summary = models.TextField(
        blank=True, 
        null=True,
        help_text="Summary of what was changed"
    )
    
    # Forensic Information - Why
    root_cause_category = models.CharField(
        max_length=100, 
        choices=ROOT_CAUSE_CHOICES,
        blank=True, 
        null=True,
        help_text="Category of root cause"
    )
    root_cause_analysis = models.TextField(
        blank=True, 
        null=True,
        help_text="Detailed analysis of why the drift occurred"
    )
    
    def __str__(self):
        return f"{self.resource_name} ({self.severity})"
    
    def time_to_detection(self):
        """Calculate time between change and detection"""
        if self.change_timestamp:
            delta = self.detected_at - self.change_timestamp
            return delta
        return None
