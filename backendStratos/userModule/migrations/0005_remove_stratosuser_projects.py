# Generated by Django 5.1.5 on 2025-02-09 16:54

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('userModule', '0004_stratosuser_address_stratosuser_city_and_more'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='stratosuser',
            name='projects',
        ),
    ]
