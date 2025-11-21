from django.db import migrations, models

class Migration(migrations.Migration):

    initial = True

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='Environment',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(help_text='Friendly name for this environment (e.g., Production, Staging)', max_length=100)),
                ('provider', models.CharField(choices=[('AWS', 'Amazon Web Services'), ('GCP', 'Google Cloud Platform'), ('Azure', 'Microsoft Azure')], default='AWS', max_length=20)),
                ('aws_access_key', models.CharField(blank=True, max_length=255, null=True)),
                ('aws_secret_key', models.CharField(blank=True, max_length=255, null=True)),
                ('iac_repo_url', models.URLField(blank=True, help_text='URL of the Infrastructure as Code repository', max_length=500, null=True)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
            ],
        ),
    ]
