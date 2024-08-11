import ipaddress
from django import forms
from .models import NetworkScanningSession
from .utils.validators.number_range_validator import port_range_number_range_validator, threat_count_number_range_validator


class NetworkScanningSessionForm(forms.ModelForm):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['scanning_session_name'].widget = forms.TextInput(attrs={"type": "text", "class": "form-control", "placeholder": self.fields['scanning_session_name'].label})
        self.fields['base_ip_address'].widget = forms.TextInput(attrs={"type": "text", "class": "form-control", "placeholder": self.fields['base_ip_address'].label})
        self.fields['ip_range'].widget = forms.TextInput(attrs={"type": "text", "class": "form-control", "placeholder": self.fields['ip_range'].label})

    class Meta:
        fields = ['scanning_session_name', 'base_ip_address', 'ip_range', 'random_or_not']
        model = NetworkScanningSession


    def clean(self):
        cleaned_data = super().clean()
        try:
            ipaddress.IPv4Network(cleaned_data['base_ip_address'] + '/' + str(cleaned_data['ip_range']))
        except Exception as e:
            raise forms.ValidationError({'base_ip_address': ["Error raised from ipaddress.IPv4Network class.", e]})
        



class NetworkScanningSessionUpdateForm(NetworkScanningSessionForm):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['base_ip_address'].disabled = True
        self.fields['ip_range'].disabled = True
        self.fields['random_or_not'].disabled = True





class NetworkScanningSessionDeletionForm(forms.Form):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['confirm_deletion'] = forms.CharField(widget = forms.TextInput(attrs={"type": "text", "class": "form-control", "placeholder": "Type 'yes' and submit form."}), label="Confirm Deletion")


    def clean(self):
        cleaned_data = super().clean()
        if cleaned_data['confirm_deletion'].strip().lower() != 'yes':
            raise forms.ValidationError({'confirm_deletion': "Only 'yes' is acceptable."})
        




class NetworkScanningForm(forms.Form):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['port_number'].widget = forms.TextInput(attrs={"type": "text", "class": "form-control", "placeholder": self.fields['port_number'].label})
        self.fields['thread_count'].widget = forms.TextInput(attrs={"type": "text", "class": "form-control", "placeholder": self.fields['thread_count'].label})

    SCAN_TYPE = (
        ('n', 'Select Scan Type'),
        ('ss', 'Server Status'),
        ('ps', 'Port Status')
    )
    scan_type = forms.ChoiceField(choices=SCAN_TYPE, required=True, label='Scan Type')
    port_number = forms.CharField(required=False, label='Port Number')
    thread_count = forms.CharField(required=False, label='Thread Count')


    def clean(self):
        cleaned_data = super().clean()
        scan_type = cleaned_data.get('scan_type')
        port_number = cleaned_data.get('port_number')
        thread_count = cleaned_data.get('thread_count')
        
        error_dict = dict()
        if scan_type == 'ps':
            if port_number == None:
                raise forms.ValidationError({'port_number': "Port number can not be empty when scan type is 'Port Status'."})
            else:
                try:
                    port_range_number_range_validator(port_number)
                except Exception as e:
                    error_dict['port_number'] = e

        if thread_count == None or thread_count == '':
            cleaned_data['thread_count'] = 1
        else:
            try:
                port_range_number_range_validator(thread_count)
            except Exception as e:
                error_dict['thread_count'] = e
        
        if len(error_dict.keys()) > 0:
            raise forms.ValidationError(error_dict)

        return cleaned_data





class DeviceAndOSDetailForm(forms.Form):
    def __init__(self, *args, **kwargs):
        self.form_request = kwargs.pop('form_request', None)
        super().__init__(*args, **kwargs)
        self.fields['thread_count'].widget = forms.TextInput(attrs={"type": "text", "class": "form-control", "placeholder": self.fields['thread_count'].label})

    SCAN_TYPE = (
        ('co', 'Choose an Option'),
        ('usr', 'Uploading Scan Result'),
        ('rs', 'Running Scanner')
    )

    scan_type = forms.ChoiceField(choices=SCAN_TYPE, required=True, label='Choose an Option')
    device_and_os_detail_nmap_txt_result_file = forms.FileField(required=False, label="Device and OS Detail nmap .txt Result")
    thread_count = forms.CharField(required=False, label='Thread Count')

    def clean(self):
        cleaned_data = super().clean()
        scan_type = cleaned_data.get('scan_type')
        thread_count = cleaned_data.get('thread_count')

        if scan_type == 'usr':
            if self.form_request.FILES.get('device_and_os_detail_nmap_txt_result_file') == None:
                raise forms.ValidationError({'device_and_os_detail_nmap_txt_result_file': "Nothing uploaded."})
            else:
                if str(self.form_request.FILES.get('device_and_os_detail_nmap_txt_result_file'))[-4:] != '.txt':
                    raise forms.ValidationError({'device_and_os_detail_nmap_txt_result_file': "Uploaded .txt file."})

        if scan_type == 'rs':
            if thread_count == None or thread_count == '':
                cleaned_data['thread_count'] = 1
            else:
                try:
                    port_range_number_range_validator(thread_count)
                except Exception as e:
                    forms.ValidationError({'thread_count': e})

        return cleaned_data

