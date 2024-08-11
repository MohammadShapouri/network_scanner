import socket
import re
import concurrent.futures


class PortScanner:
    def __init__(self, port_number=4, thread_count=1, timeout=10, port_status_queryset=None):
        self.port_number = int(port_number)
        self.thread_count = int(thread_count)
        self.timeout = timeout
        self.port_status_queryset = port_status_queryset



    def start_scanning(self):
        splitted_port_status_obj_list_list = self.ip_list_splitter(self.port_status_queryset, self.thread_count) # A list which contains splitted lists of IP Addresses.
        print("Port Number: " + str(self.port_number) + ".")
        print("Thread Count: " + str(self.thread_count) + ".")
        print("Timeout: " + str(self.timeout) + ".")
        pool = concurrent.futures.ThreadPoolExecutor(max_workers=self.thread_count)
        for i in range(self.thread_count):
            pool.submit(self.port_availibility_checker, splitted_port_status_obj_list_list[i], self.port_number, self.timeout)
        pool.shutdown(wait=True)
        print("Scanning Done!")



    def ip_list_splitter(self, port_status_obj_list, part_number):
        splitted_port_status_obj_list_list = list()
        list_length = len(port_status_obj_list)
        part_size = list_length // part_number

        for part in range(1, part_number+1):
            if part != (part_number):
                trimmedList = port_status_obj_list[(part_size*part)-part_size:(part_size*part)]
            else:
                trimmedList = port_status_obj_list[(part_size*part)-part_size:]
            splitted_port_status_obj_list_list.append(trimmedList)
        return splitted_port_status_obj_list_list



    def ip_addr_structure_verifier(self, ip_addr_obj):
        try:
            regex = "^((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])$"
            if re.match(regex, ip_addr_obj.ip_address) == None:
                return False
            else:
                return True
        except Exception as e:
            print(f"Something went wrong in ip_addr_structure_verifier function!: {e}")



    def availible_port_writer(self, port_status_obj):
        
        try:
            port_status_obj.is_open = 'open'

            port_status_obj.save()
        except Exception as e:
            print(f"Something went wrong in availible_server_writer function!: {e}")



    def unavailible_port_writer(self, port_status_obj):
        try:
            port_status_obj.is_open = 'close'
            port_status_obj.save()
        except Exception as e:
            print(f"Something went wrong in availible_server_writer function!: {e}")



    def incorrect_ip_writer(self, ip_addr_obj):
        try:
            ip_addr_obj.is_up = 'ic'
            ip_addr_obj.save()
        except Exception as e:
            print(f"Something went wrong in incorrect_ip_writer function!: {e}")



    def port_availibility_checker(self, port_status_obj_list, port_number, timeout):
        ip_list_length = len(port_status_obj_list)

        for i in range(ip_list_length):
            if self.ip_addr_structure_verifier(port_status_obj_list[i].related_ip_address) == True:
                tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                tcp.settimeout(timeout)
                if tcp.connect_ex((port_status_obj_list[i].related_ip_address.ip_address, port_number)) == 0:
                    self.availible_port_writer(port_status_obj_list[i])
                    print(port_status_obj_list[i].related_ip_address.ip_address + " is availible.")
                else:
                    self.unavailible_port_writer(port_status_obj_list[i])
                tcp.close()
            else:
                self.incorrect_ip_writer(port_status_obj_list[i].related_ip_address)
