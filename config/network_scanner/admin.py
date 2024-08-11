from django.contrib import admin
from .models import NetworkScanningSession, NetworkScanningSessionIPAddress, PortStatus, DeviceAndOSDetail
# Register your models here.
admin.site.register(NetworkScanningSession)
admin.site.register(NetworkScanningSessionIPAddress)
admin.site.register(PortStatus)
admin.site.register(DeviceAndOSDetail)
