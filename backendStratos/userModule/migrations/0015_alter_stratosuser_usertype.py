# Generated by Django 5.1.5 on 2025-06-07 17:04

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('userModule', '0014_alter_stratosuser_usertype'),
    ]

    operations = [
        migrations.AlterField(
            model_name='stratosuser',
            name='userType',
            field=models.CharField(choices=[('investor', 'Investor'), ('developer', 'Developer'), ('gamer', 'Gamer')], default='gamer', max_length=20),
        ),
    ]
