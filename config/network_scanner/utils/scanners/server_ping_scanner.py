import re
import random
import subprocess
import concurrent.futures
from network_scanner.models import NetworkScanningSessionIPAddress


class ServerPingScanner:
    def __init__(self, packet_count=4, thread_count=1, ip_addresses_queryset=None):
        self.packet_count = int(packet_count)
        self.thread_count = int(thread_count)
        self.ip_addresses_queryset = ip_addresses_queryset



    def start_scanning(self):
        splitted_ip_obj_list_list = self.ip_list_splitter(self.ip_addresses_queryset, self.thread_count) # A list which contains splitted lists of IP Addresses.
        print("Packet Count: " + str(self.packet_count) + ".")
        print("Thread Count: " + str(self.thread_count) + ".")
        pool = concurrent.futures.ThreadPoolExecutor(max_workers=self.thread_count)
        for i in range(self.thread_count):
            pool.submit(self.server_availibility_checker, splitted_ip_obj_list_list[i], self.packet_count)
        pool.shutdown(wait=True)
        print("Scanning Done!")



    def ip_list_splitter(self, ip_obj_list, part_number):
        splitted_ip_obj_list_list = list()
        list_length = len(ip_obj_list)
        part_size = list_length // part_number

        for part in range(1, part_number+1):
            if part != (part_number):
                trimmedList = ip_obj_list[(part_size*part)-part_size:(part_size*part)]
            else:
                trimmedList = ip_obj_list[(part_size*part)-part_size:]
            splitted_ip_obj_list_list.append(trimmedList)
        return splitted_ip_obj_list_list



    def ip_addr_structure_verifier(self, ip_addr_obj):
        try:
            regex = "^((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])$"
            if re.match(regex, ip_addr_obj.ip_address) == None:
                return False
            else:
                return True
        except Exception as e:
            print(f"Something went wrong in ip_addr_structure_verifier function!: {e}")



    def availible_server_writer(self, ip_addr_obj):
        try:
            ip_addr_obj.is_up = 'up'
            ip_addr_obj.save()
        except Exception as e:
            print(f"Something went wrong in availible_server_writer function!: {e}")



    def Unavailable_server_writer(self, ip_addr_obj):
        try:
            ip_addr_obj.is_up = 'down'
            ip_addr_obj.save()
        except Exception as e:
            print(f"Something went wrong in availible_server_writer function!: {e}")



    def incorrect_ip_writer(self, ip_addr_obj):
        try:
            ip_addr_obj.is_up = 'ic'
            ip_addr_obj.save()
        except Exception as e:
            print(f"Something went wrong in incorrect_ip_writer function!: {e}")



    def ping(self, ip_addr_obj, packet_count):
        # Returning 0 means that the sever is up.
        return subprocess.call(["ping", "-c", str(packet_count), str(ip_addr_obj.ip_address)]) == 0



    def server_availibility_checker(self, ip_obj_list, packet_count):
        ip_list_length = len(ip_obj_list)

        for i in range(ip_list_length):
            if self.ip_addr_structure_verifier(ip_obj_list[i]) == True:
                if self.ping(ip_obj_list[i], packet_count) == True:
                    self.availible_server_writer(ip_obj_list[i])
                    print(ip_obj_list[i] + " is availible.")
                else:
                    self.Unavailable_server_writer(ip_obj_list[i])
            else:
                self.incorrect_ip_writer(ip_obj_list[i])
