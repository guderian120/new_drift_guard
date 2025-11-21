from django import forms
from .models import Environment
from .utils import validate_credentials

class EnvironmentForm(forms.ModelForm):
    class Meta:
        model = Environment
        fields = ['name', 'provider', 'aws_access_key', 'aws_secret_key', 'iac_repo_url']
        widgets = {
            'name': forms.TextInput(attrs={'class': 'mt-1 block w-full rounded-md border-gray-600 bg-gray-700 text-white shadow-sm focus:border-indigo-500 focus:ring-indigo-500 sm:text-sm'}),
            'provider': forms.Select(attrs={'class': 'mt-1 block w-full rounded-md border-gray-600 bg-gray-700 text-white shadow-sm focus:border-indigo-500 focus:ring-indigo-500 sm:text-sm'}),
            'aws_access_key': forms.TextInput(attrs={'class': 'mt-1 block w-full rounded-md border-gray-600 bg-gray-700 text-white shadow-sm focus:border-indigo-500 focus:ring-indigo-500 sm:text-sm'}),
            'aws_secret_key': forms.PasswordInput(attrs={'class': 'mt-1 block w-full rounded-md border-gray-600 bg-gray-700 text-white shadow-sm focus:border-indigo-500 focus:ring-indigo-500 sm:text-sm'}),
            'iac_repo_url': forms.URLInput(attrs={'class': 'mt-1 block w-full rounded-md border-gray-600 bg-gray-700 text-white shadow-sm focus:border-indigo-500 focus:ring-indigo-500 sm:text-sm', 'placeholder': 'https://github.com/username/repo'}),
        }

    def clean(self):
        cleaned_data = super().clean()
        provider = cleaned_data.get('provider')
        aws_access_key = cleaned_data.get('aws_access_key')
        aws_secret_key = cleaned_data.get('aws_secret_key')

        if provider == 'AWS':
            is_valid, message = validate_credentials(provider, aws_access_key, aws_secret_key)
            if not is_valid:
                raise forms.ValidationError(message)
        
        return cleaned_data
