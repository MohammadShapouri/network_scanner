from typing import Any
from django.core.exceptions import ValidationError





class BaseNumberRangeValidator():
    def validate(self, value, least_acceptabe_value, most_acceptable_value):
        params = {
            "value": value,
            "least_acceptabe_value": least_acceptabe_value,
            "most_acceptable_value": most_acceptable_value
        }

        try:
            if str(value).isdigit() == False:
                raise ValidationError("%(value)s must be digit.", "only_digits", params)
            if int(value) < least_acceptabe_value or int(value) > most_acceptable_value:
                raise ValidationError("%(value)s must be between %(least_acceptabe_value)s and %(most_acceptable_value)s.", "out_of_acceptable_range", params)
        except Exception as e:
            raise ValidationError(f"{e}")



class IPRangeNumberRangeValidator(BaseNumberRangeValidator):
    def __call__(self, value):
        self.validate(value, 0, 32)



class PortRangeNumberRangeValidator(BaseNumberRangeValidator):
    def __call__(self, value):
        self.validate(value, 0, 65535)





def ip_range_number_range_validator(value):
    BaseNumberRangeValidator().validate(value, 0, 32)

def port_range_number_range_validator(value):
    BaseNumberRangeValidator().validate(value, 0, 65535)

def threat_count_number_range_validator(value):
    BaseNumberRangeValidator().validate(value, 0, 1000)
