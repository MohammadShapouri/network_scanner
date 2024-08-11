import ipaddress
from django.db.models.signals import post_save
from django.dispatch import receiver
from .models import NetworkScanningSession, NetworkScanningSessionIPAddress


@receiver(post_save, sender=NetworkScanningSession)
def create_network_scanning_session_ip_address(sender, instance, created, **kwargs):
        if created == True:
            #[str(ip) for ip in ipaddress.IPv4Network('192.0.2.0/28')]
            network_scanning_session_ip_address_obj_list = list()
            for each_ip in ipaddress.IPv4Network(instance.base_ip_address + '/' + str(instance.ip_range)):
                network_scanning_session_ip_address_obj_list.append(NetworkScanningSessionIPAddress(ip_address=str(each_ip), related_scan_session=instance, is_up='ns'))

                if len(network_scanning_session_ip_address_obj_list) == 1500:
                    NetworkScanningSessionIPAddress.objects.bulk_create(network_scanning_session_ip_address_obj_list)
                    network_scanning_session_ip_address_obj_list = list()

