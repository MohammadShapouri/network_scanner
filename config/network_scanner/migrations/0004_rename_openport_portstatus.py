# Generated by Django 5.0.6 on 2024-08-09 20:52

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('network_scanner', '0003_alter_networkscanningsessionipaddress_is_up_and_more'),
    ]

    operations = [
        migrations.RenameModel(
            old_name='OpenPort',
            new_name='PortStatus',
        ),
    ]