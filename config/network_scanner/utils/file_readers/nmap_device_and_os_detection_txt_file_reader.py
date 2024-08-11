import os
from pathlib import Path
from network_scanner.models import DeviceAndOSDetail



class NmapDeviceAndOSDetectionTxtFileReader:
    def __init__(self, file_name, ip_addresses_queryset, fill_null_values = True):
        self.file_name = file_name
        self.ip_addresses_queryset = ip_addresses_queryset
        self.fill_null_values = fill_null_values

        # Searches until it finds 'config' folder and then goes to 'tmp_nmap_txt_result_file_container' folder where files are there.
        BASE_DIR = Path(__file__).resolve()
        while str(BASE_DIR)[-6:] != 'config':
            BASE_DIR = BASE_DIR.parent
        
        self.file_path = os.path.join(BASE_DIR, 'tmp_nmap_txt_result_file_container', self.file_name)





    def convert_and_save_device_and_os_data_in_db(self):
        try:
            with open(self.file_path) as file_reader:
                self.file_data_list = file_reader.readlines()
    
            self.file_data_list = list(map(str.strip, self.file_data_list))
            extracted_data = self.convert_scan_result_data_to_dict(self.file_data_list)
            self.save_data_in_db(extracted_data)
        except FileNotFoundError:
            print("No valid file found.")
        except Exception as e:
            print(f"Something went wrong in file_reader function!: {e}")





    def convert_scan_result_data_to_dict(self, scan_result_data):
        print("Converting Text File Data...")
        i = None
        extracted_data = dict()

        for item in scan_result_data:
            if "Nmap scan report for" in item:
                i = item[21:]
                extracted_data[i] = dict()

            if "Device type: " in item:
                extracted_data[i]['device_type'] = item[13:]

            if "Running (JUST GUESSING): " in item:
                extracted_data[i]['runnung_guesses'] = item[25:]

            if "OS CPE: " in item:
                extracted_data[i]['os_cpe'] = item[8:]

            if "Aggressive OS guesses: " in item:
                extracted_data[i]['aggeressive_os'] = item[23:]

            if "No exact OS matches for host (test conditions non-ideal)." in item:
                extracted_data[i]['no_exact_os'] = item

            if "Service Info: OSs: " in item:
                extracted_data[i]['service_info_os'] = item[19:]
            
            if self.fill_null_values:
                if extracted_data[i].get("device_type") == None:
                    extracted_data[i]["device_type"] = "-----"
                if extracted_data[i].get("runnung_guesses") == None:
                    extracted_data[i]["runnung_guesses"] = "-----"
                if extracted_data[i].get("os_cpe") == None:
                    extracted_data[i]["os_cpe"] = "-----"
                if extracted_data[i].get("aggeressive_os") == None:
                    extracted_data[i]["aggeressive_os"] = "-----"
                if extracted_data[i].get("no_exact_os") == None:
                    extracted_data[i]["no_exact_os"] = "-----"  
                if extracted_data[i].get("service_info_os") == None:
                    extracted_data[i]["service_info_os"] = "-----"
        return extracted_data





    def save_data_in_db(self, extracted_data):
        for each_ip_address_obj in self.ip_addresses_queryset:
            if extracted_data.get(each_ip_address_obj.ip_address) != None:
                DeviceAndOSDetail.objects.update_or_create(
                    related_ip_address = each_ip_address_obj,
                    defaults={
                        "is_scanned": 'y',
                        "device_type": extracted_data[each_ip_address_obj.ip_address]['device_type'],
                        "runnung_guesses": extracted_data[each_ip_address_obj.ip_address]['runnung_guesses'],
                        "os_cpe": extracted_data[each_ip_address_obj.ip_address]['os_cpe'],
                        "aggeressive_os": extracted_data[each_ip_address_obj.ip_address]['aggeressive_os'],
                        "no_exact_os": extracted_data[each_ip_address_obj.ip_address]['no_exact_os'],
                        "service_info_os": extracted_data[each_ip_address_obj.ip_address]['service_info_os']
                    }
                )
            else:
                DeviceAndOSDetail.objects.update_or_create(
                    related_ip_address = each_ip_address_obj,
                    defaults= {
                        "is_scanned": 'n'
                    }
                )
