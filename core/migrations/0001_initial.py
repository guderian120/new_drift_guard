from django.db import migrations, models

class Migration(migrations.Migration):

    initial = True

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='AppSettings',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('gemini_api_key', models.CharField(blank=True, help_text='API Key for Google Gemini AI', max_length=255, null=True)),
                ('aws_access_key', models.CharField(blank=True, max_length=255, null=True)),
                ('aws_secret_key', models.CharField(blank=True, max_length=255, null=True)),
            ],
            options={
                'verbose_name': 'Application Settings',
                'verbose_name_plural': 'Application Settings',
            },
        ),
    ]
