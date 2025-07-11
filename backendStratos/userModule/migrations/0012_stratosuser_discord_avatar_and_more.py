# Generated by Django 5.1.5 on 2025-06-05 16:11

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('userModule', '0011_stratosuser_discord_id'),
    ]

    operations = [
        migrations.AddField(
            model_name='stratosuser',
            name='discord_avatar',
            field=models.CharField(blank=True, help_text='Discord avatar hash', max_length=200, null=True),
        ),
        migrations.AddField(
            model_name='stratosuser',
            name='discord_discriminator',
            field=models.CharField(blank=True, help_text='Discord discriminator (legacy)', max_length=10, null=True),
        ),
        migrations.AddField(
            model_name='stratosuser',
            name='discord_global_name',
            field=models.CharField(blank=True, help_text='Discord display name', max_length=200, null=True),
        ),
        migrations.AddField(
            model_name='stratosuser',
            name='discord_username',
            field=models.CharField(blank=True, help_text='Discord username', max_length=200, null=True),
        ),
    ]
