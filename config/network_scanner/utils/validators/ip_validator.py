import re
from django.core.exceptions import ValidationError



class IPValidator():
    def __call__(self, ip_address):
        self.validate(ip_address)

    def validate(self, ip_address):
        params = {
            "ip_address": ip_address
        }
        try:
            regex = "^((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])$"
            if re.match(regex, ip_address) == None:
                raise ValidationError(message="%(ip_address)s is not a valid IP address", code="invalid_IP_address", params=params)
            else:
                return True
        except Exception as e:
            raise ValidationError(f"Something went wrong during validating IP address. {e}")





def ip_validator(ip_address):
    IPValidator().validate(ip_address)
