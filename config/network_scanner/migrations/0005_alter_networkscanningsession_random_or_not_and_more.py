# Generated by Django 5.0.6 on 2024-08-11 19:21

import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('network_scanner', '0004_rename_openport_portstatus'),
    ]

    operations = [
        migrations.AlterField(
            model_name='networkscanningsession',
            name='random_or_not',
            field=models.CharField(choices=[('r', 'Random'), ('nr', 'Not Random')], max_length=2, verbose_name='IP scanning method'),
        ),
        migrations.AlterField(
            model_name='portstatus',
            name='related_ip_address',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='network_scanner.networkscanningsessionipaddress', verbose_name='Related IP Address'),
        ),
        migrations.CreateModel(
            name='DeviceAndOSDetail',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('is_scanned', models.CharField(choices=[('y', 'Yes'), ('n', 'No')], max_length=3, verbose_name='Is any scan data availible for this IP address?')),
                ('device_type', models.CharField(blank=True, max_length=150, null=True, verbose_name='Device Type')),
                ('runnung_guesses', models.CharField(blank=True, max_length=150, null=True, verbose_name='Runnung Guesses')),
                ('os_cpe', models.CharField(blank=True, max_length=250, null=True, verbose_name='OS cpe')),
                ('aggeressive_os', models.CharField(blank=True, max_length=250, null=True, verbose_name='Aggeressive OS')),
                ('no_exact_os', models.CharField(blank=True, max_length=150, null=True, verbose_name='No Exact OS')),
                ('service_info_os', models.CharField(blank=True, max_length=150, null=True, verbose_name='Service Info OS')),
                ('related_ip_address', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='network_scanner.networkscanningsessionipaddress', verbose_name='Related IP Address')),
            ],
        ),
    ]