import socket
import re
import subprocess
import tempfile
import concurrent.futures
from network_scanner.models import DeviceAndOSDetail


class DeviceAndOSTypeScanner:
    def __init__(self, thread_count, system_password, ip_address_queryset=None, fill_null_values=True):
        self.thread_count = int(thread_count)
        self.ip_address_queryset = ip_address_queryset
        self.fill_null_values = fill_null_values
        self.system_password = system_password

        for each_ip_address_obj in self.ip_address_queryset:
            daod_obj = DeviceAndOSDetail.objects.filter(related_ip_address=each_ip_address_obj)
            if len(daod_obj) == 0:
                DeviceAndOSDetail.objects.create(related_ip_address=each_ip_address_obj)




    def start_scanning(self):
        splitted_ip_address_obj_list_list = self.ip_list_splitter(self.ip_address_queryset, self.thread_count)
        print("Thread Count: " + str(self.thread_count) + ".")
        pool = concurrent.futures.ThreadPoolExecutor(max_workers=self.thread_count)
        for i in range(self.thread_count):
            pool.submit(self.device_and_os_type_detector, splitted_ip_address_obj_list_list[i])
        pool.shutdown(wait=True)
        print("Scanning Done!")



    def ip_list_splitter(self, ip_address_obj_list, part_number):
        splitted_ip_address_obj_list_list = list()
        list_length = len(ip_address_obj_list)
        part_size = list_length // part_number

        for part in range(1, part_number+1):
            if part != (part_number):
                trimmedList = ip_address_obj_list[(part_size*part)-part_size:(part_size*part)]
            else:
                trimmedList = ip_address_obj_list[(part_size*part)-part_size:]
            splitted_ip_address_obj_list_list.append(trimmedList)
        return splitted_ip_address_obj_list_list



    def ip_addr_structure_verifier(self, ip_addr_obj):
        try:
            regex = "^((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])$"
            if re.match(regex, ip_addr_obj.ip_address) == None:
                return False
            else:
                return True
        except Exception as e:
            print(f"Something went wrong in ip_addr_structure_verifier function!: {e}")



    def save_data_in_db(self, extracted_data):
        if extracted_data.get('ip') != None:
            DeviceAndOSDetail.objects.update_or_create(
                related_ip_address = extracted_data['ip'],
                defaults={
                    "is_scanned": 'y',
                    "device_type": extracted_data['device_type'],
                    "runnung_guesses": extracted_data['runnung_guesses'],
                    "os_cpe": extracted_data['os_cpe'],
                    "aggeressive_os": extracted_data['aggeressive_os'],
                    "no_exact_os": extracted_data['no_exact_os'],
                    "service_info_os": extracted_data['service_info_os']
                }
            )



    def incorrect_ip_writer(self, ip_addr_obj):
        try:
            ip_addr_obj.is_up = 'ic'
            ip_addr_obj.save()
        except Exception as e:
            print(f"Something went wrong in incorrect_ip_writer function!: {e}")



    def device_and_os_type_detector(self, ip_address_obj_list):
        ip_list_length = len(ip_address_obj_list)

        for i in range(ip_list_length):
            if self.ip_addr_structure_verifier(ip_address_obj_list[i]) == True:
                with tempfile.TemporaryFile() as tempf:
                    proc = subprocess.Popen(['echo', self.system_password, '|', 'sudo', '-S', 'nmap', '-sV', '-O', '-v', ip_address_obj_list[i].ip_address], stdout=tempf)
                    proc.wait()
                    tempf.seek(0)
                    scan_result_data = tempf.read().decode('utf-8').split('\n')

                    extracted_data = dict()

                    for item in scan_result_data:
                        if "Nmap scan report for" in item:
                            extracted_data = dict()
                            extracted_data['ip'] = item[21:]

                        if "Device type: " in item:
                            extracted_data['device_type'] = item[13:]

                        if "Running (JUST GUESSING): " in item:
                            extracted_data['runnung_guesses'] = item[25:]

                        if "OS CPE: " in item:
                            extracted_data['os_cpe'] = item[8:]

                        if "Aggressive OS guesses: " in item:
                            extracted_data['aggeressive_os'] = item[23:]

                        if "No exact OS matches for host (test conditions non-ideal)." in item:
                            extracted_data['no_exact_os'] = item

                        if "Service Info: OSs: " in item:
                            extracted_data['service_info_os'] = item[19:]
                        
                        if self.fill_null_values:
                            if extracted_data.get("device_type") == None:
                                extracted_data["device_type"] = "-----"
                            if extracted_data.get("runnung_guesses") == None:
                                extracted_data["runnung_guesses"] = "-----"
                            if extracted_data.get("os_cpe") == None:
                                extracted_data["os_cpe"] = "-----"
                            if extracted_data.get("aggeressive_os") == None:
                                extracted_data["aggeressive_os"] = "-----"
                            if extracted_data.get("no_exact_os") == None:
                                extracted_data["no_exact_os"] = "-----"  
                            if extracted_data.get("service_info_os") == None:
                                extracted_data["service_info_os"] = "-----"
            else:
                self.incorrect_ip_writer(ip_address_obj_list[i])
