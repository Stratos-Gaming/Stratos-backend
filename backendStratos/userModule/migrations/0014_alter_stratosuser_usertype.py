# Generated by Django 5.1.5 on 2025-06-07 17:01

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('userModule', '0013_stratosuser_usertype_usersocialconnection_and_more'),
    ]

    operations = [
        migrations.AlterField(
            model_name='stratosuser',
            name='userType',
            field=models.CharField(choices=[('investor', 'Investor'), ('developer', 'Developer'), ('gamer', 'Gamer')], default='free', max_length=20),
        ),
    ]
