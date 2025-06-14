# Generated by Django 5.1.5 on 2025-06-09 10:45

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('userModule', '0015_alter_stratosuser_usertype'),
    ]

    operations = [
        migrations.CreateModel(
            name='UserType',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('type', models.CharField(choices=[('investor', 'Investor'), ('developer', 'Developer'), ('gamer', 'Gamer')], max_length=20, unique=True)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
            ],
        ),
        migrations.RemoveField(
            model_name='stratosuser',
            name='userType',
        ),
        migrations.AddField(
            model_name='stratosuser',
            name='user_types',
            field=models.ManyToManyField(blank=True, related_name='users', to='userModule.usertype'),
        ),
    ]
