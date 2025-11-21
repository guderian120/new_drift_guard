from django.db import migrations, models

class Migration(migrations.Migration):

    dependencies = [
        ('core', '0001_initial'),
    ]

    operations = [
        migrations.AddField(
            model_name='appsettings',
            name='git_repo_url',
            field=models.URLField(blank=True, help_text='URL of the infrastructure Git repository', max_length=500, null=True),
        ),
    ]
