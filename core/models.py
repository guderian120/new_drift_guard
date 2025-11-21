from django.db import models

class AppSettings(models.Model):
    # AI Model Choices
    GEMINI_MODEL_CHOICES = [
        ('models/gemini-2.5-flash', 'Gemini 2.5 Flash (Recommended - Fast & Efficient)'),
        ('models/gemini-2.5-pro', 'Gemini 2.5 Pro (Most Capable)'),
        ('models/gemini-2.0-flash-exp', 'Gemini 2.0 Flash Experimental'),
        ('models/gemini-2.0-flash', 'Gemini 2.0 Flash (Stable)'),
    ]
    
    gemini_api_key = models.CharField(
        max_length=255, 
        blank=True, 
        null=True, 
        help_text="API Key for Google Gemini AI"
    )
    gemini_model = models.CharField(
        max_length=100,
        choices=GEMINI_MODEL_CHOICES,
        default='models/gemini-2.5-flash',
        help_text="Select which Gemini AI model to use for the chatbot"
    )
    
    class Meta:
        verbose_name = "Application Settings"
        verbose_name_plural = "Application Settings"

    def __str__(self):
        return "DriftGuard Configuration"

    @classmethod
    def get_solo(cls):
        obj, created = cls.objects.get_or_create(pk=1)
        return obj
