from django import forms
from .models import AppSettings

class AppSettingsForm(forms.ModelForm):
    class Meta:
        model = AppSettings
        fields = ['gemini_api_key', 'gemini_model']
        widgets = {
            'gemini_api_key': forms.PasswordInput(attrs={
                'class': 'mt-1 block w-full rounded-md border-gray-600 bg-gray-700 text-white shadow-sm focus:border-indigo-500 focus:ring-indigo-500 sm:text-sm'
            }),
            'gemini_model': forms.Select(attrs={
                'class': 'mt-1 block w-full rounded-md border-gray-600 bg-gray-700 text-white shadow-sm focus:border-indigo-500 focus:ring-indigo-500 sm:text-sm'
            }),
        }

    def clean_gemini_api_key(self):
        api_key = self.cleaned_data.get('gemini_api_key')
        if not api_key and self.instance.pk:
            return self.instance.gemini_api_key
        return api_key
