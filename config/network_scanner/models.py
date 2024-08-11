from django.db import models
from network_scanner.utils.validators.ip_validator import IPValidator, ip_validator
from network_scanner.utils.validators.number_range_validator import IPRangeNumberRangeValidator, PortRangeNumberRangeValidator, ip_range_number_range_validator, port_range_number_range_validator


IS_OPEN = (
    ('open', "Open"),
    ('close', "Close"),
    ('ns', "Not Scanned")
)

IS_SCANNED = (
    ('y', "Yes"),
    ('n', "No")
)

# Create your models here.
class NetworkScanningSession(models.Model):
    RANDOM_OR_NOT = (
        ('r', "Random"),
        ('nr', "Not Random"),
    )

    scanning_session_name   = models.CharField(max_length=50, blank=False, null=False, verbose_name="Name of this scan")
    base_ip_address         = models.CharField(max_length=15, blank=False, null=False, verbose_name="IP address", validators=[ip_validator])
    ip_range                = models.PositiveIntegerField(blank=False, null=False, verbose_name="IP range", validators=[ip_range_number_range_validator])
    random_or_not           = models.CharField(choices=RANDOM_OR_NOT, max_length=2, blank=False, null=False, verbose_name="IP scanning method")
    creation_date           = models.DateTimeField(auto_now=True, blank=False, null=False, verbose_name="Creation date")

    def __str__(self):
        return str(self.scanning_session_name) + " - " + str(self.base_ip_address) + "/" + str(self.ip_range)





class NetworkScanningSessionIPAddress(models.Model):
    IS_UP = (
        ('up', "Up"),
        ('down', "Down"),
        ('ns', "Not Scanned"),
        ('ic', "Incorrect IP Address")
    )

    ip_address              = models.CharField(max_length=15, blank=False, null=False, verbose_name="IP address", validators=[ip_validator])
    related_scan_session    = models.ForeignKey('NetworkScanningSession', on_delete=models.CASCADE, verbose_name="Related scan session")
    is_up                   = models.CharField(choices=IS_UP, max_length=4, blank=False, null=False, verbose_name="Server status")

    def __str__(self):
        return str(self.related_scan_session) + " - " + str(self.ip_address) + " - " + str(self.is_up)





class PortStatus(models.Model):
    related_ip_address  = models.ForeignKey('NetworkScanningSessionIPAddress', on_delete=models.CASCADE, verbose_name="Related IP Address")
    port = models.CharField(max_length=15, blank=False, null=False, verbose_name="Port Number", validators=[port_range_number_range_validator])
    is_open = models.CharField(choices=IS_OPEN, max_length=5, blank=False, null=False, verbose_name="port status")

    def __str__(self):
        return str(self.related_ip_address) + " - " + str(self.port) + " - " + str(self.is_open)





class DeviceAndOSDetail(models.Model):
    related_ip_address  = models.ForeignKey('NetworkScanningSessionIPAddress', on_delete=models.CASCADE, verbose_name="Related IP Address")
    is_scanned          = models.CharField(choices=IS_SCANNED, max_length=3, blank=False, null=False, verbose_name="Is any scan data availible for this IP address?")
    device_type         = models.CharField(max_length=150, blank=True, null=True, verbose_name="Device Type")
    runnung_guesses     = models.CharField(max_length=150, blank=True, null=True, verbose_name="Runnung Guesses")
    os_cpe              = models.CharField(max_length=250, blank=True, null=True, verbose_name="OS cpe")
    aggeressive_os      = models.CharField(max_length=250, blank=True, null=True, verbose_name="Aggeressive OS")
    no_exact_os         = models.CharField(max_length=150, blank=True, null=True, verbose_name="No Exact OS")
    service_info_os     = models.CharField(max_length=150, blank=True, null=True, verbose_name="Service Info OS")

    def __str__(self):
        return str(self.related_ip_address) + " - " + str(self.device_type)
