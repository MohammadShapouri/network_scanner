from django.views.generic import DeleteView, CreateView, ListView, UpdateView, FormView
from django.views import View
from django.urls import reverse_lazy
from .forms import NetworkScanningSessionForm, NetworkScanningSessionUpdateForm, NetworkScanningForm, NetworkScanningSessionDeletionForm, DeviceAndOSDetailForm, NetworkScanningSessionDownServersDeletionForm
from .models import NetworkScanningSession, NetworkScanningSessionIPAddress, PortStatus, IS_OPEN, IS_SCANNED
from django.shortcuts import render, get_object_or_404
from django.core.paginator import Paginator, EmptyPage, PageNotAnInteger
from .utils.scanners.server_ping_scanner import ServerPingScanner
from .utils.scanners.port_scanner import PortScanner
from .utils.file_readers.nmap_device_and_os_detection_txt_file_reader import NmapDeviceAndOSDetectionTxtFileReader
from .utils.scanners.device_and_os_type_scanner import DeviceAndOSTypeScanner
from django.core.files.storage import FileSystemStorage
from django.db.models import Q
from pathlib import Path
from datetime import datetime
from django.db import connection
import os
import subprocess
import platform
import tempfile
# Create your views here.

class NetworkScanningSessionListView(ListView):
    model = NetworkScanningSession
    template_name = 'scanning-session-list-page.html'





class NetworkScanningSessionCreationView(CreateView):
    template_name = 'scanning-session-creation-page.html'
    form_class = NetworkScanningSessionForm
    success_url = reverse_lazy('list-session')





class NetworkScanningSessionUpdateView(UpdateView):
    model = NetworkScanningSession
    template_name = 'scanning-session-update-page.html'
    form_class = NetworkScanningSessionUpdateForm

    def get_success_url(self):
        return reverse_lazy('session-detail', kwargs={'pk': self.kwargs.get('pk')})





class NetworkScanningSessionDeletionView(DeleteView):
    model = NetworkScanningSession
    template_name = 'session-delete-page.html'
    form_class = NetworkScanningSessionDeletionForm

    def get_success_url(self):
        return reverse_lazy('list-session')





class NetworkScanningSessionDetailView(View):
    template_name = 'scanning-session-detail-page.html'

    def get(self, request, *args, **kwargs):
        network_scanning_session_obj = get_object_or_404(NetworkScanningSession, pk=self.kwargs.get('pk'))
        ip_addresses_list = None

        search_where_clause = str()
        if request.GET.get('search_input') != None and request.GET.get('search_input') != '':
            search_input = request.GET.get('search_input')
            search_where_clause = f"and network_scanner_networkscanningsessionipaddress.ip_address == \"{search_input}\""


        port_status = dict()
        if request.GET.get('filter_input') != None and request.GET.get('filter_input') != '':
            search_input = request.GET.get('search_input')
            if request.GET.get('filter_input') == 'all':
                ip_addresses_list = NetworkScanningSessionIPAddress.objects.raw(
                f"""
                    SELECT network_scanner_networkscanningsession.*, network_scanner_networkscanningsessionipaddress.id AS networkscanningsessionipaddress_id, network_scanner_networkscanningsessionipaddress.ip_address, network_scanner_networkscanningsessionipaddress.is_up,
                    group_concat(network_scanner_PortStatus.port, ',') AS 'port_numbers', group_concat(network_scanner_PortStatus.is_open, ',') AS 'is_opens'
                    from network_scanner_networkscanningsession
                    LEFT JOIN
                    network_scanner_networkscanningsessionipaddress on network_scanner_networkscanningsession.id == network_scanner_networkscanningsessionipaddress.related_scan_session_id
                    LEFT JOIN
                    network_scanner_PortStatus on network_scanner_networkscanningsessionipaddress.id == network_scanner_PortStatus.related_ip_address_id
                    where network_scanner_networkscanningsession.id == {network_scanning_session_obj.pk} {search_where_clause} group by network_scanner_networkscanningsessionipaddress.id
                """
                )

                port_data = NetworkScanningSessionIPAddress.objects.raw(
                f"""
                    SELECT network_scanner_networkscanningsession.*, network_scanner_networkscanningsessionipaddress.id AS networkscanningsessionipaddress_id, network_scanner_networkscanningsessionipaddress.ip_address, network_scanner_networkscanningsessionipaddress.is_up,
                    group_concat(network_scanner_PortStatus.port, ',') AS 'port_numbers', group_concat(network_scanner_PortStatus.is_open, ',') AS 'is_opens'
                    from network_scanner_networkscanningsession
                    LEFT JOIN
                    network_scanner_networkscanningsessionipaddress on network_scanner_networkscanningsession.id == network_scanner_networkscanningsessionipaddress.related_scan_session_id
                    LEFT JOIN
                    network_scanner_PortStatus on network_scanner_networkscanningsessionipaddress.id == network_scanner_PortStatus.related_ip_address_id
                    where network_scanner_networkscanningsession.id == {network_scanning_session_obj.pk} and network_scanner_PortStatus.port <> '' {search_where_clause} group by network_scanner_networkscanningsessionipaddress.id
                """
                )

                for each_port_data in port_data:
                    port_status[each_port_data.ip_address] = []

                    if each_port_data.port_numbers != None:
                        each_ip_address_port_number_list = str(each_port_data.port_numbers).split(',')
                        each_ip_address_is_open_list = str(each_port_data.is_opens).split(',')

                        for i in range(len(each_ip_address_port_number_list)):
                            port_status[each_port_data.ip_address].append([each_ip_address_port_number_list[i], each_ip_address_is_open_list[i]])

            elif request.GET.get('filter_input') == 'scanned':
                ip_addresses_list = NetworkScanningSessionIPAddress.objects.raw(
                f"""
                    SELECT network_scanner_networkscanningsession.*, network_scanner_networkscanningsessionipaddress.id AS networkscanningsessionipaddress_id, network_scanner_networkscanningsessionipaddress.ip_address, network_scanner_networkscanningsessionipaddress.is_up,
                    group_concat(network_scanner_PortStatus.port, ',') AS 'port_numbers', group_concat(network_scanner_PortStatus.is_open, ',') AS 'is_opens'
                    from network_scanner_networkscanningsession
                    LEFT JOIN
                    network_scanner_networkscanningsessionipaddress on network_scanner_networkscanningsession.id == network_scanner_networkscanningsessionipaddress.related_scan_session_id
                    LEFT JOIN
                    network_scanner_PortStatus on network_scanner_networkscanningsessionipaddress.id == network_scanner_PortStatus.related_ip_address_id
                    where network_scanner_networkscanningsession.id == {network_scanning_session_obj.pk} and network_scanner_networkscanningsessionipaddress.is_up != 'ns' {search_where_clause} group by network_scanner_networkscanningsessionipaddress.id
                """
                )

                port_data = NetworkScanningSessionIPAddress.objects.raw(
                f"""
                    SELECT network_scanner_networkscanningsession.*, network_scanner_networkscanningsessionipaddress.id AS networkscanningsessionipaddress_id, network_scanner_networkscanningsessionipaddress.ip_address, network_scanner_networkscanningsessionipaddress.is_up,
                    group_concat(network_scanner_PortStatus.port, ',') AS 'port_numbers', group_concat(network_scanner_PortStatus.is_open, ',') AS 'is_opens'
                    from network_scanner_networkscanningsession
                    LEFT JOIN
                    network_scanner_networkscanningsessionipaddress on network_scanner_networkscanningsession.id == network_scanner_networkscanningsessionipaddress.related_scan_session_id
                    LEFT JOIN
                    network_scanner_PortStatus on network_scanner_networkscanningsessionipaddress.id == network_scanner_PortStatus.related_ip_address_id
                    where network_scanner_networkscanningsession.id == {network_scanning_session_obj.pk} and network_scanner_PortStatus.port <> '' and network_scanner_networkscanningsessionipaddress.is_up != 'ns' {search_where_clause} group by network_scanner_networkscanningsessionipaddress.id
                """
                )

                for each_port_data in port_data:
                    port_status[each_port_data.ip_address] = []

                    if each_port_data.port_numbers != None:
                        each_ip_address_port_number_list = str(each_port_data.port_numbers).split(',')
                        each_ip_address_is_open_list = str(each_port_data.is_opens).split(',')

                        for i in range(len(each_ip_address_port_number_list)):
                            port_status[each_port_data.ip_address].append([each_ip_address_port_number_list[i], each_ip_address_is_open_list[i]])

            elif request.GET.get('filter_input') == 'up':
                ip_addresses_list = NetworkScanningSessionIPAddress.objects.raw(
                f"""
                    SELECT network_scanner_networkscanningsession.*, network_scanner_networkscanningsessionipaddress.id AS networkscanningsessionipaddress_id, network_scanner_networkscanningsessionipaddress.ip_address, network_scanner_networkscanningsessionipaddress.is_up,
                    group_concat(network_scanner_PortStatus.port, ',') AS 'port_numbers', group_concat(network_scanner_PortStatus.is_open, ',') AS 'is_opens'
                    from network_scanner_networkscanningsession
                    LEFT JOIN
                    network_scanner_networkscanningsessionipaddress on network_scanner_networkscanningsession.id == network_scanner_networkscanningsessionipaddress.related_scan_session_id
                    LEFT JOIN
                    network_scanner_PortStatus on network_scanner_networkscanningsessionipaddress.id == network_scanner_PortStatus.related_ip_address_id
                    where network_scanner_networkscanningsession.id == {network_scanning_session_obj.pk} and network_scanner_networkscanningsessionipaddress.is_up == 'up' {search_where_clause} group by network_scanner_networkscanningsessionipaddress.id
                """
                )


                port_data = NetworkScanningSessionIPAddress.objects.raw(
                f"""
                    SELECT network_scanner_networkscanningsession.*, network_scanner_networkscanningsessionipaddress.id AS networkscanningsessionipaddress_id, network_scanner_networkscanningsessionipaddress.ip_address, network_scanner_networkscanningsessionipaddress.is_up,
                    group_concat(network_scanner_PortStatus.port, ',') AS 'port_numbers', group_concat(network_scanner_PortStatus.is_open, ',') AS 'is_opens'
                    from network_scanner_networkscanningsession
                    LEFT JOIN
                    network_scanner_networkscanningsessionipaddress on network_scanner_networkscanningsession.id == network_scanner_networkscanningsessionipaddress.related_scan_session_id
                    LEFT JOIN
                    network_scanner_PortStatus on network_scanner_networkscanningsessionipaddress.id == network_scanner_PortStatus.related_ip_address_id
                    where network_scanner_networkscanningsession.id == {network_scanning_session_obj.pk} and network_scanner_PortStatus.port <> '' and network_scanner_networkscanningsessionipaddress.is_up == 'up' {search_where_clause} group by network_scanner_networkscanningsessionipaddress.id
                """
                )

                for each_port_data in port_data:
                    port_status[each_port_data.ip_address] = []

                    if each_port_data.port_numbers != None:
                        each_ip_address_port_number_list = str(each_port_data.port_numbers).split(',')
                        each_ip_address_is_open_list = str(each_port_data.is_opens).split(',')

                        for i in range(len(each_ip_address_port_number_list)):
                            port_status[each_port_data.ip_address].append([each_ip_address_port_number_list[i], each_ip_address_is_open_list[i]])

            elif request.GET.get('filter_input') == 'down':
                ip_addresses_list = NetworkScanningSessionIPAddress.objects.raw(
                f"""
                    SELECT network_scanner_networkscanningsession.*, network_scanner_networkscanningsessionipaddress.id AS networkscanningsessionipaddress_id, network_scanner_networkscanningsessionipaddress.ip_address, network_scanner_networkscanningsessionipaddress.is_up,
                    group_concat(network_scanner_PortStatus.port, ',') AS 'port_numbers', group_concat(network_scanner_PortStatus.is_open, ',') AS 'is_opens'
                    from network_scanner_networkscanningsession
                    LEFT JOIN
                    network_scanner_networkscanningsessionipaddress on network_scanner_networkscanningsession.id == network_scanner_networkscanningsessionipaddress.related_scan_session_id
                    LEFT JOIN
                    network_scanner_PortStatus on network_scanner_networkscanningsessionipaddress.id == network_scanner_PortStatus.related_ip_address_id
                    where network_scanner_networkscanningsession.id == {network_scanning_session_obj.pk} and network_scanner_networkscanningsessionipaddress.is_up == 'down' {search_where_clause} group by network_scanner_networkscanningsessionipaddress.id
                """
                )

                port_data = NetworkScanningSessionIPAddress.objects.raw(
                f"""
                    SELECT network_scanner_networkscanningsession.*, network_scanner_networkscanningsessionipaddress.id AS networkscanningsessionipaddress_id, network_scanner_networkscanningsessionipaddress.ip_address, network_scanner_networkscanningsessionipaddress.is_up,
                    group_concat(network_scanner_PortStatus.port, ',') AS 'port_numbers', group_concat(network_scanner_PortStatus.is_open, ',') AS 'is_opens'
                    from network_scanner_networkscanningsession
                    LEFT JOIN
                    network_scanner_networkscanningsessionipaddress on network_scanner_networkscanningsession.id == network_scanner_networkscanningsessionipaddress.related_scan_session_id
                    LEFT JOIN
                    network_scanner_PortStatus on network_scanner_networkscanningsessionipaddress.id == network_scanner_PortStatus.related_ip_address_id
                    where network_scanner_networkscanningsession.id == {network_scanning_session_obj.pk} and network_scanner_PortStatus.port <> '' and network_scanner_networkscanningsessionipaddress.is_up == 'down' {search_where_clause} group by network_scanner_networkscanningsessionipaddress.id
                """
                )

                for each_port_data in port_data:
                    port_status[each_port_data.ip_address] = []

                    if each_port_data.port_numbers != None:
                        each_ip_address_port_number_list = str(each_port_data.port_numbers).split(',')
                        each_ip_address_is_open_list = str(each_port_data.is_opens).split(',')

                        for i in range(len(each_ip_address_port_number_list)):
                            port_status[each_port_data.ip_address].append([each_ip_address_port_number_list[i], each_ip_address_is_open_list[i]])

            elif request.GET.get('filter_input') == 'not-scanned':
                ip_addresses_list = NetworkScanningSessionIPAddress.objects.raw(
                f"""
                    SELECT network_scanner_networkscanningsession.*, network_scanner_networkscanningsessionipaddress.id AS networkscanningsessionipaddress_id, network_scanner_networkscanningsessionipaddress.ip_address, network_scanner_networkscanningsessionipaddress.is_up,
                    group_concat(network_scanner_PortStatus.port, ',') AS 'port_numbers', group_concat(network_scanner_PortStatus.is_open, ',') AS 'is_opens'
                    from network_scanner_networkscanningsession
                    LEFT JOIN
                    network_scanner_networkscanningsessionipaddress on network_scanner_networkscanningsession.id == network_scanner_networkscanningsessionipaddress.related_scan_session_id
                    LEFT JOIN
                    network_scanner_PortStatus on network_scanner_networkscanningsessionipaddress.id == network_scanner_PortStatus.related_ip_address_id
                    where network_scanner_networkscanningsession.id == {network_scanning_session_obj.pk} and network_scanner_networkscanningsessionipaddress.is_up == 'ns' {search_where_clause} group by network_scanner_networkscanningsessionipaddress.id
                """
                )

                port_data = NetworkScanningSessionIPAddress.objects.raw(
                f"""
                    SELECT network_scanner_networkscanningsession.*, network_scanner_networkscanningsessionipaddress.id AS networkscanningsessionipaddress_id, network_scanner_networkscanningsessionipaddress.ip_address, network_scanner_networkscanningsessionipaddress.is_up,
                    group_concat(network_scanner_PortStatus.port, ',') AS 'port_numbers', group_concat(network_scanner_PortStatus.is_open, ',') AS 'is_opens'
                    from network_scanner_networkscanningsession
                    LEFT JOIN
                    network_scanner_networkscanningsessionipaddress on network_scanner_networkscanningsession.id == network_scanner_networkscanningsessionipaddress.related_scan_session_id
                    LEFT JOIN
                    network_scanner_PortStatus on network_scanner_networkscanningsessionipaddress.id == network_scanner_PortStatus.related_ip_address_id
                    where network_scanner_networkscanningsession.id == {network_scanning_session_obj.pk} and network_scanner_PortStatus.port <> '' and network_scanner_networkscanningsessionipaddress.is_up == 'ns' {search_where_clause} group by network_scanner_networkscanningsessionipaddress.id
                """
                )

                for each_port_data in port_data:
                    port_status[each_port_data.ip_address] = []

                    if each_port_data.port_numbers != None:
                        each_ip_address_port_number_list = str(each_port_data.port_numbers).split(',')
                        each_ip_address_is_open_list = str(each_port_data.is_opens).split(',')

                        for i in range(len(each_ip_address_port_number_list)):
                            port_status[each_port_data.ip_address].append([each_ip_address_port_number_list[i], each_ip_address_is_open_list[i]])

            else:
                ip_addresses_list = list()
        else:
            ip_addresses_list = NetworkScanningSessionIPAddress.objects.raw(
            f"""
                SELECT network_scanner_networkscanningsession.*, network_scanner_networkscanningsessionipaddress.id AS networkscanningsessionipaddress_id, network_scanner_networkscanningsessionipaddress.ip_address, network_scanner_networkscanningsessionipaddress.is_up,
                group_concat(network_scanner_PortStatus.port, ',') AS 'port_numbers', group_concat(network_scanner_PortStatus.is_open, ',') AS 'is_opens'
                from network_scanner_networkscanningsession
                LEFT JOIN
                network_scanner_networkscanningsessionipaddress on network_scanner_networkscanningsession.id == network_scanner_networkscanningsessionipaddress.related_scan_session_id
                LEFT JOIN
                network_scanner_PortStatus on network_scanner_networkscanningsessionipaddress.id == network_scanner_PortStatus.related_ip_address_id
                where network_scanner_networkscanningsession.id == {network_scanning_session_obj.pk} {search_where_clause} group by network_scanner_networkscanningsessionipaddress.id
            """
            )

            port_data = NetworkScanningSessionIPAddress.objects.raw(
            f"""
                SELECT network_scanner_networkscanningsession.*, network_scanner_networkscanningsessionipaddress.id AS networkscanningsessionipaddress_id, network_scanner_networkscanningsessionipaddress.ip_address, network_scanner_networkscanningsessionipaddress.is_up,
                group_concat(network_scanner_PortStatus.port, ',') AS 'port_numbers', group_concat(network_scanner_PortStatus.is_open, ',') AS 'is_opens'
                from network_scanner_networkscanningsession
                LEFT JOIN
                network_scanner_networkscanningsessionipaddress on network_scanner_networkscanningsession.id == network_scanner_networkscanningsessionipaddress.related_scan_session_id
                LEFT JOIN
                network_scanner_PortStatus on network_scanner_networkscanningsessionipaddress.id == network_scanner_PortStatus.related_ip_address_id
                where network_scanner_networkscanningsession.id == {network_scanning_session_obj.pk} and network_scanner_PortStatus.port <> '' {search_where_clause} group by network_scanner_networkscanningsessionipaddress.id
            """
            )

            for each_port_data in port_data:
                port_status[each_port_data.ip_address] = []

                if each_port_data.port_numbers != None:
                    each_ip_address_port_number_list = str(each_port_data.port_numbers).split(',')
                    each_ip_address_is_open_list = str(each_port_data.is_opens).split(',')

                    for i in range(len(each_ip_address_port_number_list)):
                        port_status[each_port_data.ip_address].append([each_ip_address_port_number_list[i], each_ip_address_is_open_list[i]])

            # ['id', 'scanning_session_name', 'base_ip_address', 'ip_range', 'random_or_not', 'creation_date', 'ip_address', 'is_up', 'port_numbers', 'is_opens']
            # print(ip_addresses_list.columns)

        if request.GET.get('filter_input') in ['all', 'scanned', 'not-scanned', 'up', 'down']:
            paginator_obj = Paginator(ip_addresses_list, 250)

            page_number = request.GET.get('page')
            try:
                selected_page = paginator_obj.get_page(page_number)
            except PageNotAnInteger:
                selected_page = paginator_obj.get_page(1)
            except EmptyPage:
                selected_page = paginator_obj.get_page(page_number)
        else:
            selected_page = ip_addresses_list

        data = {
            "object": network_scanning_session_obj,
            "number_of_ip_addresses": len(ip_addresses_list),
            "ip_address_selected_page_list": selected_page,
            "port_status": port_status,
            "is_open_choices": IS_OPEN,
            "network_scanning_form": NetworkScanningForm(),
            "filter_input": request.GET.get('filter_input')
        }
        return render(request, self.template_name, data)



    def post(self, request, *args, **kwargs):
        network_scanning_session_obj = get_object_or_404(NetworkScanningSession, pk=self.kwargs.get('pk'))
        # ip_addresses_list = NetworkScanningSessionIPAddress.objects.filter(related_scan_session=network_scanning_session_obj.pk)

        form = NetworkScanningForm(request.POST)
        if form.is_valid():
            ip_addresses_queryset = None
            if network_scanning_session_obj.random_or_not == 'r':
                ip_addresses_queryset = NetworkScanningSessionIPAddress.objects.filter(related_scan_session=network_scanning_session_obj).order_by('?')
            else:
                ip_addresses_queryset = NetworkScanningSessionIPAddress.objects.filter(related_scan_session=network_scanning_session_obj)


            if form.cleaned_data.get('what_to_scan') == 'not_scanned':
                ip_addresses_queryset = ip_addresses_queryset.filter(is_up='ns')
            elif form.cleaned_data.get('what_to_scan') == 'availible':
                ip_addresses_queryset = ip_addresses_queryset.filter(is_up='up')
            elif form.cleaned_data.get('what_to_scan') == 'not_availible':
                ip_addresses_queryset = ip_addresses_queryset.filter(is_up='down')


            if form.cleaned_data.get('scan_type') == 'ss':
                sps = ServerPingScanner(4, form.cleaned_data.get('number_of_threads'), ip_addresses_queryset)
                sps.start_scanning()
            elif form.cleaned_data.get('scan_type') == 'ps':
                open_ports_pre_bulit_obj_list = list()
                port_number = form.cleaned_data.get('port_number')
                for each_ip_address in ip_addresses_queryset:
                    open_port_obj = PortStatus.objects.filter(Q(related_ip_address=each_ip_address) & Q(port=port_number))
                    if len(open_port_obj) == 0:
                        open_ports_pre_bulit_obj_list.append(PortStatus(related_ip_address=each_ip_address, port=port_number, is_open='ns'))
                PortStatus.objects.bulk_create(open_ports_pre_bulit_obj_list)

                port_status_queryset = None
                if network_scanning_session_obj.random_or_not == 'r':
                    port_status_queryset = PortStatus.objects.filter(Q(related_ip_address__related_scan_session=network_scanning_session_obj)& Q(port=port_number)).select_related('related_ip_address').order_by('?')
                else:
                    port_status_queryset = PortStatus.objects.filter(Q(related_ip_address__related_scan_session=network_scanning_session_obj)& Q(port=port_number)).select_related('related_ip_address')

                ps = PortScanner(port_number, form.cleaned_data.get('number_of_threads'), 10, port_status_queryset)
                ps.start_scanning()


        search_where_clause = str()
        if request.GET.get('search_input') != None and request.GET.get('search_input') != '':
            search_input = request.GET.get('search_input')
            search_where_clause = f"and network_scanner_networkscanningsessionipaddress.ip_address == \"{search_input}\""


        port_status = dict()
        if request.GET.get('filter_input') != None and request.GET.get('filter_input') != '':
            search_input = request.GET.get('search_input')
            if request.GET.get('filter_input') == 'all':
                ip_addresses_list = NetworkScanningSessionIPAddress.objects.raw(
                f"""
                    SELECT network_scanner_networkscanningsession.*, network_scanner_networkscanningsessionipaddress.id AS networkscanningsessionipaddress_id, network_scanner_networkscanningsessionipaddress.ip_address, network_scanner_networkscanningsessionipaddress.is_up,
                    group_concat(network_scanner_PortStatus.port, ',') AS 'port_numbers', group_concat(network_scanner_PortStatus.is_open, ',') AS 'is_opens'
                    from network_scanner_networkscanningsession
                    LEFT JOIN
                    network_scanner_networkscanningsessionipaddress on network_scanner_networkscanningsession.id == network_scanner_networkscanningsessionipaddress.related_scan_session_id
                    LEFT JOIN
                    network_scanner_PortStatus on network_scanner_networkscanningsessionipaddress.id == network_scanner_PortStatus.related_ip_address_id
                    where network_scanner_networkscanningsession.id == {network_scanning_session_obj.pk} {search_where_clause} group by network_scanner_networkscanningsessionipaddress.id
                """
                )

                port_data = NetworkScanningSessionIPAddress.objects.raw(
                f"""
                    SELECT network_scanner_networkscanningsession.*, network_scanner_networkscanningsessionipaddress.id AS networkscanningsessionipaddress_id, network_scanner_networkscanningsessionipaddress.ip_address, network_scanner_networkscanningsessionipaddress.is_up,
                    group_concat(network_scanner_PortStatus.port, ',') AS 'port_numbers', group_concat(network_scanner_PortStatus.is_open, ',') AS 'is_opens'
                    from network_scanner_networkscanningsession
                    LEFT JOIN
                    network_scanner_networkscanningsessionipaddress on network_scanner_networkscanningsession.id == network_scanner_networkscanningsessionipaddress.related_scan_session_id
                    LEFT JOIN
                    network_scanner_PortStatus on network_scanner_networkscanningsessionipaddress.id == network_scanner_PortStatus.related_ip_address_id
                    where network_scanner_networkscanningsession.id == {network_scanning_session_obj.pk} and network_scanner_PortStatus.port <> '' {search_where_clause} group by network_scanner_networkscanningsessionipaddress.id
                """
                )

                for each_port_data in port_data:
                    port_status[each_port_data.ip_address] = []

                    if each_port_data.port_numbers != None:
                        each_ip_address_port_number_list = str(each_port_data.port_numbers).split(',')
                        each_ip_address_is_open_list = str(each_port_data.is_opens).split(',')

                        for i in range(len(each_ip_address_port_number_list)):
                            port_status[each_port_data.ip_address].append([each_ip_address_port_number_list[i], each_ip_address_is_open_list[i]])

            elif request.GET.get('filter_input') == 'scanned':
                ip_addresses_list = NetworkScanningSessionIPAddress.objects.raw(
                f"""
                    SELECT network_scanner_networkscanningsession.*, network_scanner_networkscanningsessionipaddress.id AS networkscanningsessionipaddress_id, network_scanner_networkscanningsessionipaddress.ip_address, network_scanner_networkscanningsessionipaddress.is_up,
                    group_concat(network_scanner_PortStatus.port, ',') AS 'port_numbers', group_concat(network_scanner_PortStatus.is_open, ',') AS 'is_opens'
                    from network_scanner_networkscanningsession
                    LEFT JOIN
                    network_scanner_networkscanningsessionipaddress on network_scanner_networkscanningsession.id == network_scanner_networkscanningsessionipaddress.related_scan_session_id
                    LEFT JOIN
                    network_scanner_PortStatus on network_scanner_networkscanningsessionipaddress.id == network_scanner_PortStatus.related_ip_address_id
                    where network_scanner_networkscanningsession.id == {network_scanning_session_obj.pk} and network_scanner_networkscanningsessionipaddress.is_up != 'ns' {search_where_clause} group by network_scanner_networkscanningsessionipaddress.id
                """
                )

                port_data = NetworkScanningSessionIPAddress.objects.raw(
                f"""
                    SELECT network_scanner_networkscanningsession.*, network_scanner_networkscanningsessionipaddress.id AS networkscanningsessionipaddress_id, network_scanner_networkscanningsessionipaddress.ip_address, network_scanner_networkscanningsessionipaddress.is_up,
                    group_concat(network_scanner_PortStatus.port, ',') AS 'port_numbers', group_concat(network_scanner_PortStatus.is_open, ',') AS 'is_opens'
                    from network_scanner_networkscanningsession
                    LEFT JOIN
                    network_scanner_networkscanningsessionipaddress on network_scanner_networkscanningsession.id == network_scanner_networkscanningsessionipaddress.related_scan_session_id
                    LEFT JOIN
                    network_scanner_PortStatus on network_scanner_networkscanningsessionipaddress.id == network_scanner_PortStatus.related_ip_address_id
                    where network_scanner_networkscanningsession.id == {network_scanning_session_obj.pk} and network_scanner_PortStatus.port <> '' and network_scanner_networkscanningsessionipaddress.is_up != 'ns' {search_where_clause} group by network_scanner_networkscanningsessionipaddress.id
                """
                )

                for each_port_data in port_data:
                    port_status[each_port_data.ip_address] = []

                    if each_port_data.port_numbers != None:
                        each_ip_address_port_number_list = str(each_port_data.port_numbers).split(',')
                        each_ip_address_is_open_list = str(each_port_data.is_opens).split(',')

                        for i in range(len(each_ip_address_port_number_list)):
                            port_status[each_port_data.ip_address].append([each_ip_address_port_number_list[i], each_ip_address_is_open_list[i]])

            elif request.GET.get('filter_input') == 'up':
                ip_addresses_list = NetworkScanningSessionIPAddress.objects.raw(
                f"""
                    SELECT network_scanner_networkscanningsession.*, network_scanner_networkscanningsessionipaddress.id AS networkscanningsessionipaddress_id, network_scanner_networkscanningsessionipaddress.ip_address, network_scanner_networkscanningsessionipaddress.is_up,
                    group_concat(network_scanner_PortStatus.port, ',') AS 'port_numbers', group_concat(network_scanner_PortStatus.is_open, ',') AS 'is_opens'
                    from network_scanner_networkscanningsession
                    LEFT JOIN
                    network_scanner_networkscanningsessionipaddress on network_scanner_networkscanningsession.id == network_scanner_networkscanningsessionipaddress.related_scan_session_id
                    LEFT JOIN
                    network_scanner_PortStatus on network_scanner_networkscanningsessionipaddress.id == network_scanner_PortStatus.related_ip_address_id
                    where network_scanner_networkscanningsession.id == {network_scanning_session_obj.pk} and network_scanner_networkscanningsessionipaddress.is_up == 'up' {search_where_clause} group by network_scanner_networkscanningsessionipaddress.id
                """
                )


                port_data = NetworkScanningSessionIPAddress.objects.raw(
                f"""
                    SELECT network_scanner_networkscanningsession.*, network_scanner_networkscanningsessionipaddress.id AS networkscanningsessionipaddress_id, network_scanner_networkscanningsessionipaddress.ip_address, network_scanner_networkscanningsessionipaddress.is_up,
                    group_concat(network_scanner_PortStatus.port, ',') AS 'port_numbers', group_concat(network_scanner_PortStatus.is_open, ',') AS 'is_opens'
                    from network_scanner_networkscanningsession
                    LEFT JOIN
                    network_scanner_networkscanningsessionipaddress on network_scanner_networkscanningsession.id == network_scanner_networkscanningsessionipaddress.related_scan_session_id
                    LEFT JOIN
                    network_scanner_PortStatus on network_scanner_networkscanningsessionipaddress.id == network_scanner_PortStatus.related_ip_address_id
                    where network_scanner_networkscanningsession.id == {network_scanning_session_obj.pk} and network_scanner_PortStatus.port <> '' and network_scanner_networkscanningsessionipaddress.is_up == 'up' {search_where_clause} group by network_scanner_networkscanningsessionipaddress.id
                """
                )

                for each_port_data in port_data:
                    port_status[each_port_data.ip_address] = []

                    if each_port_data.port_numbers != None:
                        each_ip_address_port_number_list = str(each_port_data.port_numbers).split(',')
                        each_ip_address_is_open_list = str(each_port_data.is_opens).split(',')

                        for i in range(len(each_ip_address_port_number_list)):
                            port_status[each_port_data.ip_address].append([each_ip_address_port_number_list[i], each_ip_address_is_open_list[i]])

            elif request.GET.get('filter_input') == 'down':
                ip_addresses_list = NetworkScanningSessionIPAddress.objects.raw(
                f"""
                    SELECT network_scanner_networkscanningsession.*, network_scanner_networkscanningsessionipaddress.id AS networkscanningsessionipaddress_id, network_scanner_networkscanningsessionipaddress.ip_address, network_scanner_networkscanningsessionipaddress.is_up,
                    group_concat(network_scanner_PortStatus.port, ',') AS 'port_numbers', group_concat(network_scanner_PortStatus.is_open, ',') AS 'is_opens'
                    from network_scanner_networkscanningsession
                    LEFT JOIN
                    network_scanner_networkscanningsessionipaddress on network_scanner_networkscanningsession.id == network_scanner_networkscanningsessionipaddress.related_scan_session_id
                    LEFT JOIN
                    network_scanner_PortStatus on network_scanner_networkscanningsessionipaddress.id == network_scanner_PortStatus.related_ip_address_id
                    where network_scanner_networkscanningsession.id == {network_scanning_session_obj.pk} and network_scanner_networkscanningsessionipaddress.is_up == 'down' {search_where_clause} group by network_scanner_networkscanningsessionipaddress.id
                """
                )

                port_data = NetworkScanningSessionIPAddress.objects.raw(
                f"""
                    SELECT network_scanner_networkscanningsession.*, network_scanner_networkscanningsessionipaddress.id AS networkscanningsessionipaddress_id, network_scanner_networkscanningsessionipaddress.ip_address, network_scanner_networkscanningsessionipaddress.is_up,
                    group_concat(network_scanner_PortStatus.port, ',') AS 'port_numbers', group_concat(network_scanner_PortStatus.is_open, ',') AS 'is_opens'
                    from network_scanner_networkscanningsession
                    LEFT JOIN
                    network_scanner_networkscanningsessionipaddress on network_scanner_networkscanningsession.id == network_scanner_networkscanningsessionipaddress.related_scan_session_id
                    LEFT JOIN
                    network_scanner_PortStatus on network_scanner_networkscanningsessionipaddress.id == network_scanner_PortStatus.related_ip_address_id
                    where network_scanner_networkscanningsession.id == {network_scanning_session_obj.pk} and network_scanner_PortStatus.port <> '' and network_scanner_networkscanningsessionipaddress.is_up == 'down' {search_where_clause} group by network_scanner_networkscanningsessionipaddress.id
                """
                )

                for each_port_data in port_data:
                    port_status[each_port_data.ip_address] = []

                    if each_port_data.port_numbers != None:
                        each_ip_address_port_number_list = str(each_port_data.port_numbers).split(',')
                        each_ip_address_is_open_list = str(each_port_data.is_opens).split(',')

                        for i in range(len(each_ip_address_port_number_list)):
                            port_status[each_port_data.ip_address].append([each_ip_address_port_number_list[i], each_ip_address_is_open_list[i]])

            elif request.GET.get('filter_input') == 'not-scanned':
                ip_addresses_list = NetworkScanningSessionIPAddress.objects.raw(
                f"""
                    SELECT network_scanner_networkscanningsession.*, network_scanner_networkscanningsessionipaddress.id AS networkscanningsessionipaddress_id, network_scanner_networkscanningsessionipaddress.ip_address, network_scanner_networkscanningsessionipaddress.is_up,
                    group_concat(network_scanner_PortStatus.port, ',') AS 'port_numbers', group_concat(network_scanner_PortStatus.is_open, ',') AS 'is_opens'
                    from network_scanner_networkscanningsession
                    LEFT JOIN
                    network_scanner_networkscanningsessionipaddress on network_scanner_networkscanningsession.id == network_scanner_networkscanningsessionipaddress.related_scan_session_id
                    LEFT JOIN
                    network_scanner_PortStatus on network_scanner_networkscanningsessionipaddress.id == network_scanner_PortStatus.related_ip_address_id
                    where network_scanner_networkscanningsession.id == {network_scanning_session_obj.pk} and network_scanner_networkscanningsessionipaddress.is_up == 'ns' {search_where_clause} group by network_scanner_networkscanningsessionipaddress.id
                """
                )

                port_data = NetworkScanningSessionIPAddress.objects.raw(
                f"""
                    SELECT network_scanner_networkscanningsession.*, network_scanner_networkscanningsessionipaddress.id AS networkscanningsessionipaddress_id, network_scanner_networkscanningsessionipaddress.ip_address, network_scanner_networkscanningsessionipaddress.is_up,
                    group_concat(network_scanner_PortStatus.port, ',') AS 'port_numbers', group_concat(network_scanner_PortStatus.is_open, ',') AS 'is_opens'
                    from network_scanner_networkscanningsession
                    LEFT JOIN
                    network_scanner_networkscanningsessionipaddress on network_scanner_networkscanningsession.id == network_scanner_networkscanningsessionipaddress.related_scan_session_id
                    LEFT JOIN
                    network_scanner_PortStatus on network_scanner_networkscanningsessionipaddress.id == network_scanner_PortStatus.related_ip_address_id
                    where network_scanner_networkscanningsession.id == {network_scanning_session_obj.pk} and network_scanner_PortStatus.port <> '' and network_scanner_networkscanningsessionipaddress.is_up == 'ns' {search_where_clause} group by network_scanner_networkscanningsessionipaddress.id
                """
                )

                for each_port_data in port_data:
                    port_status[each_port_data.ip_address] = []

                    if each_port_data.port_numbers != None:
                        each_ip_address_port_number_list = str(each_port_data.port_numbers).split(',')
                        each_ip_address_is_open_list = str(each_port_data.is_opens).split(',')

                        for i in range(len(each_ip_address_port_number_list)):
                            port_status[each_port_data.ip_address].append([each_ip_address_port_number_list[i], each_ip_address_is_open_list[i]])

            else:
                ip_addresses_list = list()
        else:
            ip_addresses_list = NetworkScanningSessionIPAddress.objects.raw(
            f"""
                SELECT network_scanner_networkscanningsession.*, network_scanner_networkscanningsessionipaddress.id AS networkscanningsessionipaddress_id, network_scanner_networkscanningsessionipaddress.ip_address, network_scanner_networkscanningsessionipaddress.is_up,
                group_concat(network_scanner_PortStatus.port, ',') AS 'port_numbers', group_concat(network_scanner_PortStatus.is_open, ',') AS 'is_opens'
                from network_scanner_networkscanningsession
                LEFT JOIN
                network_scanner_networkscanningsessionipaddress on network_scanner_networkscanningsession.id == network_scanner_networkscanningsessionipaddress.related_scan_session_id
                LEFT JOIN
                network_scanner_PortStatus on network_scanner_networkscanningsessionipaddress.id == network_scanner_PortStatus.related_ip_address_id
                where network_scanner_networkscanningsession.id == {network_scanning_session_obj.pk} {search_where_clause} group by network_scanner_networkscanningsessionipaddress.id
            """
            )

            port_data = NetworkScanningSessionIPAddress.objects.raw(
            f"""
                SELECT network_scanner_networkscanningsession.*, network_scanner_networkscanningsessionipaddress.id AS networkscanningsessionipaddress_id, network_scanner_networkscanningsessionipaddress.ip_address, network_scanner_networkscanningsessionipaddress.is_up,
                group_concat(network_scanner_PortStatus.port, ',') AS 'port_numbers', group_concat(network_scanner_PortStatus.is_open, ',') AS 'is_opens'
                from network_scanner_networkscanningsession
                LEFT JOIN
                network_scanner_networkscanningsessionipaddress on network_scanner_networkscanningsession.id == network_scanner_networkscanningsessionipaddress.related_scan_session_id
                LEFT JOIN
                network_scanner_PortStatus on network_scanner_networkscanningsessionipaddress.id == network_scanner_PortStatus.related_ip_address_id
                where network_scanner_networkscanningsession.id == {network_scanning_session_obj.pk} and network_scanner_PortStatus.port <> '' {search_where_clause} group by network_scanner_networkscanningsessionipaddress.id
            """
            )

            for each_port_data in port_data:
                port_status[each_port_data.ip_address] = []

                if each_port_data.port_numbers != None:
                    each_ip_address_port_number_list = str(each_port_data.port_numbers).split(',')
                    each_ip_address_is_open_list = str(each_port_data.is_opens).split(',')

                    for i in range(len(each_ip_address_port_number_list)):
                        port_status[each_port_data.ip_address].append([each_ip_address_port_number_list[i], each_ip_address_is_open_list[i]])

            # ['id', 'scanning_session_name', 'base_ip_address', 'ip_range', 'random_or_not', 'creation_date', 'ip_address', 'is_up', 'port_numbers', 'is_opens']
            # print(ip_addresses_list.columns)

        if request.GET.get('filter_input') in ['all', 'scanned', 'not-scanned', 'up', 'down']:
            paginator_obj = Paginator(ip_addresses_list, 250)

            page_number = request.GET.get('page')
            try:
                selected_page = paginator_obj.get_page(page_number)
            except PageNotAnInteger:
                selected_page = paginator_obj.get_page(1)
            except EmptyPage:
                selected_page = paginator_obj.get_page(page_number)
        else:
            selected_page = ip_addresses_list


        data = {
            "object": network_scanning_session_obj,
            "number_of_ip_addresses": len(ip_addresses_list),
            "ip_address_selected_page_list": selected_page,
            "port_status": port_status,
            "is_open_choices": IS_OPEN,
            "network_scanning_form": form,
            "filter_input": request.GET.get('filter_input')
        }
        return render(request, self.template_name, data)
    




class NetworkScanningSessionDeviceDetailView(View):
    template_name = 'scanning-session-device-detail-page.html'

    def get(self, request, *args, **kwargs):
        network_scanning_session_obj = get_object_or_404(NetworkScanningSession, pk=self.kwargs.get('pk'))

        search_where_clause = str()
        if request.GET.get('search_input') != None and request.GET.get('search_input') != '':
            search_input = request.GET.get('search_input')
            search_where_clause = f"and network_scanner_networkscanningsessionipaddress.ip_address == \"{search_input}\""


        port_status = dict()
        if request.GET.get('filter_input') != None and request.GET.get('filter_input') != '':
            search_input = request.GET.get('search_input')
            if request.GET.get('filter_input') == 'all':
                ip_addresses_list = NetworkScanningSessionIPAddress.objects.raw(
                f"""
                    SELECT network_scanner_networkscanningsession.*, network_scanner_networkscanningsessionipaddress.id AS networkscanningsessionipaddress_id, network_scanner_networkscanningsessionipaddress.ip_address, network_scanner_networkscanningsessionipaddress.is_up,
                    network_scanner_DeviceAndOSDetail.*
                    from network_scanner_networkscanningsession
                    LEFT JOIN
                    network_scanner_networkscanningsessionipaddress on network_scanner_networkscanningsession.id == network_scanner_networkscanningsessionipaddress.related_scan_session_id
                    LEFT JOIN
                    network_scanner_DeviceAndOSDetail on network_scanner_networkscanningsessionipaddress.id == network_scanner_DeviceAndOSDetail.related_ip_address_id
                    where network_scanner_networkscanningsession.id == {network_scanning_session_obj.pk} {search_where_clause} group by network_scanner_networkscanningsessionipaddress.id
                """
                )

            elif request.GET.get('filter_input') == 'scanned':
                ip_addresses_list = NetworkScanningSessionIPAddress.objects.raw(
                f"""
                    SELECT network_scanner_networkscanningsession.*, network_scanner_networkscanningsessionipaddress.id AS networkscanningsessionipaddress_id, network_scanner_networkscanningsessionipaddress.ip_address, network_scanner_networkscanningsessionipaddress.is_up,
                    network_scanner_DeviceAndOSDetail.*
                    from network_scanner_networkscanningsession
                    LEFT JOIN
                    network_scanner_networkscanningsessionipaddress on network_scanner_networkscanningsession.id == network_scanner_networkscanningsessionipaddress.related_scan_session_id
                    LEFT JOIN
                    network_scanner_DeviceAndOSDetail on network_scanner_networkscanningsessionipaddress.id == network_scanner_DeviceAndOSDetail.related_ip_address_id
                    where network_scanner_networkscanningsession.id == {network_scanning_session_obj.pk} and network_scanner_networkscanningsessionipaddress.is_up != 'ns' {search_where_clause} group by network_scanner_networkscanningsessionipaddress.id
                """
                )

            elif request.GET.get('filter_input') == 'up':
                ip_addresses_list = NetworkScanningSessionIPAddress.objects.raw(
                f"""
                    SELECT network_scanner_networkscanningsession.*, network_scanner_networkscanningsessionipaddress.id AS networkscanningsessionipaddress_id, network_scanner_networkscanningsessionipaddress.ip_address, network_scanner_networkscanningsessionipaddress.is_up,
                    network_scanner_DeviceAndOSDetail.*
                    from network_scanner_networkscanningsession
                    LEFT JOIN
                    network_scanner_networkscanningsessionipaddress on network_scanner_networkscanningsession.id == network_scanner_networkscanningsessionipaddress.related_scan_session_id
                    LEFT JOIN
                    network_scanner_DeviceAndOSDetail on network_scanner_networkscanningsessionipaddress.id == network_scanner_DeviceAndOSDetail.related_ip_address_id
                    where network_scanner_networkscanningsession.id == {network_scanning_session_obj.pk} and network_scanner_networkscanningsessionipaddress.is_up == 'up' {search_where_clause} group by network_scanner_networkscanningsessionipaddress.id
                """
                )

            elif request.GET.get('filter_input') == 'down':
                ip_addresses_list = NetworkScanningSessionIPAddress.objects.raw(
                f"""
                    SELECT network_scanner_networkscanningsession.*, network_scanner_networkscanningsessionipaddress.id AS networkscanningsessionipaddress_id, network_scanner_networkscanningsessionipaddress.ip_address, network_scanner_networkscanningsessionipaddress.is_up,
                    network_scanner_DeviceAndOSDetail.*
                    from network_scanner_networkscanningsession
                    LEFT JOIN
                    network_scanner_networkscanningsessionipaddress on network_scanner_networkscanningsession.id == network_scanner_networkscanningsessionipaddress.related_scan_session_id
                    LEFT JOIN
                    network_scanner_DeviceAndOSDetail on network_scanner_networkscanningsessionipaddress.id == network_scanner_DeviceAndOSDetail.related_ip_address_id
                    where network_scanner_networkscanningsession.id == {network_scanning_session_obj.pk} and network_scanner_networkscanningsessionipaddress.is_up == 'down' {search_where_clause} group by network_scanner_networkscanningsessionipaddress.id
                """
                )

            elif request.GET.get('filter_input') == 'not-scanned':
                ip_addresses_list = NetworkScanningSessionIPAddress.objects.raw(
                f"""
                    SELECT network_scanner_networkscanningsession.*, network_scanner_networkscanningsessionipaddress.id AS networkscanningsessionipaddress_id, network_scanner_networkscanningsessionipaddress.ip_address, network_scanner_networkscanningsessionipaddress.is_up,
                    network_scanner_DeviceAndOSDetail.*
                    from network_scanner_networkscanningsession
                    LEFT JOIN
                    network_scanner_networkscanningsessionipaddress on network_scanner_networkscanningsession.id == network_scanner_networkscanningsessionipaddress.related_scan_session_id
                    LEFT JOIN
                    network_scanner_DeviceAndOSDetail on network_scanner_networkscanningsessionipaddress.id == network_scanner_DeviceAndOSDetail.related_ip_address_id
                    where network_scanner_networkscanningsession.id == {network_scanning_session_obj.pk} and network_scanner_networkscanningsessionipaddress.is_up == 'ns' {search_where_clause} group by network_scanner_networkscanningsessionipaddress.id
                """
                )

            else:
                ip_addresses_list = list()
        else:
            ip_addresses_list = NetworkScanningSessionIPAddress.objects.raw(
            f"""
                SELECT network_scanner_networkscanningsession.*, network_scanner_networkscanningsessionipaddress.id AS networkscanningsessionipaddress_id, network_scanner_networkscanningsessionipaddress.ip_address, network_scanner_networkscanningsessionipaddress.is_up,
                network_scanner_DeviceAndOSDetail.*
                from network_scanner_networkscanningsession
                LEFT JOIN
                network_scanner_networkscanningsessionipaddress on network_scanner_networkscanningsession.id == network_scanner_networkscanningsessionipaddress.related_scan_session_id
                LEFT JOIN
                network_scanner_DeviceAndOSDetail on network_scanner_networkscanningsessionipaddress.id == network_scanner_DeviceAndOSDetail.related_ip_address_id
                where network_scanner_networkscanningsession.id == {network_scanning_session_obj.pk} {search_where_clause} group by network_scanner_networkscanningsessionipaddress.id
            """
            )

            # ['id', 'scanning_session_name', 'base_ip_address', 'ip_range', 'random_or_not', 'creation_date', 'ip_address', 'is_up', 'port_numbers', 'is_opens']
            # print(ip_addresses_list.columns)

        if request.GET.get('filter_input') in ['all', 'scanned', 'not-scanned', 'up', 'down']:
            paginator_obj = Paginator(ip_addresses_list, 250)

            page_number = request.GET.get('page')
            try:
                selected_page = paginator_obj.get_page(page_number)
            except PageNotAnInteger:
                selected_page = paginator_obj.get_page(1)
            except EmptyPage:
                selected_page = paginator_obj.get_page(page_number)
        else:
            selected_page = ip_addresses_list


        data = {
            "object": network_scanning_session_obj,
            "number_of_ip_addresses": len(ip_addresses_list),
            "ip_address_selected_page_list": selected_page,
            "is_scanned": IS_SCANNED,
            "network_device_scanning_form": DeviceAndOSDetailForm(form_request=request),
            "filter_input": request.GET.get('filter_input')
        }
        return render(request, self.template_name, data)



    def post(self, request, *args, **kwargs):
        network_scanning_session_obj = get_object_or_404(NetworkScanningSession, pk=self.kwargs.get('pk'))
        # ip_addresses_list = NetworkScanningSessionIPAddress.objects.filter(related_scan_session=network_scanning_session_obj.pk)
        form = DeviceAndOSDetailForm(request.POST, request.FILES, form_request=request)
        if form.is_valid():
            ip_address_queryset = NetworkScanningSessionIPAddress.objects.filter(related_scan_session=network_scanning_session_obj)
            if form.cleaned_data.get('scan_type') == 'usr':
                in_memory_nmap_txt_result_file = self.request.FILES['device_and_os_detail_nmap_txt_result_file']
                in_memory_nmap_txt_result_file_name = in_memory_nmap_txt_result_file.name[:-4] + str(datetime.now()).replace(' ', '_').replace('-', '_').replace(':', '_').replace('.', '_') + in_memory_nmap_txt_result_file.name[-4:]
                # # Searches until it finds 'config' folder.
                # BASE_DIR = Path(__file__).resolve()
                # while str(BASE_DIR)[-6:] != 'config':
                #     BASE_DIR = BASE_DIR.parent
                BASE_DIR = Path(__file__).resolve().parent.parent
                FileSystemStorage(location=os.path.join(BASE_DIR, 'tmp_nmap_txt_result_file_container')).save(in_memory_nmap_txt_result_file_name, in_memory_nmap_txt_result_file)

                nmap_file_reader = NmapDeviceAndOSDetectionTxtFileReader(in_memory_nmap_txt_result_file_name, ip_address_queryset)
                nmap_file_reader.convert_and_save_device_and_os_data_in_db()
            elif form.cleaned_data.get('scan_type') == 'rs':
                    
                scan_result_data = None
                with tempfile.TemporaryFile() as tempf:
                    proc = subprocess.Popen(['nmap', '--version'], stdout=tempf)
                    proc.wait()
                    tempf.seek(0)
                    scan_result_data = tempf.read().decode('utf-8').split('\n')

                if platform.system().lower()=='windows':
                    form.add_error('scan_type', 'This type of scan can not be used in Windows systems.')

                elif 'Nmap version'.lower() not in scan_result_data[0].lower():
                    form.add_error('scan_type', 'Nmap not found. Check if it was installed before.')
                
                else:
                    ip_addresses_queryset = None
                    if network_scanning_session_obj.random_or_not == 'r':
                        ip_addresses_queryset = NetworkScanningSessionIPAddress.objects.filter(related_scan_session=network_scanning_session_obj).order_by('?')
                    else:
                        ip_addresses_queryset = NetworkScanningSessionIPAddress.objects.filter(related_scan_session=network_scanning_session_obj)

                    if form.cleaned_data.get('what_to_scan') == 'not_scanned':
                        ip_addresses_queryset = ip_addresses_queryset.filter(is_up='ns')
                    elif form.cleaned_data.get('what_to_scan') == 'availible':
                        ip_addresses_queryset = ip_addresses_queryset.filter(is_up='up')
                    elif form.cleaned_data.get('what_to_scan') == 'not_availible':
                        ip_addresses_queryset = ip_addresses_queryset.filter(is_up='down')

                    daots = DeviceAndOSTypeScanner(form.cleaned_data.get('number_of_threads'), form.cleaned_data.get('system_password'), ip_addresses_queryset)
                    daots.start_scanning()


        search_where_clause = str()
        if request.GET.get('search_input') != None and request.GET.get('search_input') != '':
            search_input = request.GET.get('search_input')
            search_where_clause = f"and network_scanner_networkscanningsessionipaddress.ip_address == \"{search_input}\""


        port_status = dict()
        if request.GET.get('filter_input') != None and request.GET.get('filter_input') != '':
            search_input = request.GET.get('search_input')
            if request.GET.get('filter_input') == 'all':
                ip_addresses_list = NetworkScanningSessionIPAddress.objects.raw(
                f"""
                    SELECT network_scanner_networkscanningsession.*, network_scanner_networkscanningsessionipaddress.id AS networkscanningsessionipaddress_id, network_scanner_networkscanningsessionipaddress.ip_address, network_scanner_networkscanningsessionipaddress.is_up,
                    network_scanner_DeviceAndOSDetail.*
                    from network_scanner_networkscanningsession
                    LEFT JOIN
                    network_scanner_networkscanningsessionipaddress on network_scanner_networkscanningsession.id == network_scanner_networkscanningsessionipaddress.related_scan_session_id
                    LEFT JOIN
                    network_scanner_DeviceAndOSDetail on network_scanner_networkscanningsessionipaddress.id == network_scanner_DeviceAndOSDetail.related_ip_address_id
                    where network_scanner_networkscanningsession.id == {network_scanning_session_obj.pk} {search_where_clause} group by network_scanner_networkscanningsessionipaddress.id
                """
                )

            elif request.GET.get('filter_input') == 'scanned':
                ip_addresses_list = NetworkScanningSessionIPAddress.objects.raw(
                f"""
                    SELECT network_scanner_networkscanningsession.*, network_scanner_networkscanningsessionipaddress.id AS networkscanningsessionipaddress_id, network_scanner_networkscanningsessionipaddress.ip_address, network_scanner_networkscanningsessionipaddress.is_up,
                    network_scanner_DeviceAndOSDetail.*
                    from network_scanner_networkscanningsession
                    LEFT JOIN
                    network_scanner_networkscanningsessionipaddress on network_scanner_networkscanningsession.id == network_scanner_networkscanningsessionipaddress.related_scan_session_id
                    LEFT JOIN
                    network_scanner_DeviceAndOSDetail on network_scanner_networkscanningsessionipaddress.id == network_scanner_DeviceAndOSDetail.related_ip_address_id
                    where network_scanner_networkscanningsession.id == {network_scanning_session_obj.pk} and network_scanner_networkscanningsessionipaddress.is_up != 'ns' {search_where_clause} group by network_scanner_networkscanningsessionipaddress.id
                """
                )

            elif request.GET.get('filter_input') == 'up':
                ip_addresses_list = NetworkScanningSessionIPAddress.objects.raw(
                f"""
                    SELECT network_scanner_networkscanningsession.*, network_scanner_networkscanningsessionipaddress.id AS networkscanningsessionipaddress_id, network_scanner_networkscanningsessionipaddress.ip_address, network_scanner_networkscanningsessionipaddress.is_up,
                    network_scanner_DeviceAndOSDetail.*
                    from network_scanner_networkscanningsession
                    LEFT JOIN
                    network_scanner_networkscanningsessionipaddress on network_scanner_networkscanningsession.id == network_scanner_networkscanningsessionipaddress.related_scan_session_id
                    LEFT JOIN
                    network_scanner_DeviceAndOSDetail on network_scanner_networkscanningsessionipaddress.id == network_scanner_DeviceAndOSDetail.related_ip_address_id
                    where network_scanner_networkscanningsession.id == {network_scanning_session_obj.pk} and network_scanner_networkscanningsessionipaddress.is_up == 'up' {search_where_clause} group by network_scanner_networkscanningsessionipaddress.id
                """
                )

            elif request.GET.get('filter_input') == 'down':
                ip_addresses_list = NetworkScanningSessionIPAddress.objects.raw(
                f"""
                    SELECT network_scanner_networkscanningsession.*, network_scanner_networkscanningsessionipaddress.id AS networkscanningsessionipaddress_id, network_scanner_networkscanningsessionipaddress.ip_address, network_scanner_networkscanningsessionipaddress.is_up,
                    network_scanner_DeviceAndOSDetail.*
                    from network_scanner_networkscanningsession
                    LEFT JOIN
                    network_scanner_networkscanningsessionipaddress on network_scanner_networkscanningsession.id == network_scanner_networkscanningsessionipaddress.related_scan_session_id
                    LEFT JOIN
                    network_scanner_DeviceAndOSDetail on network_scanner_networkscanningsessionipaddress.id == network_scanner_DeviceAndOSDetail.related_ip_address_id
                    where network_scanner_networkscanningsession.id == {network_scanning_session_obj.pk} and network_scanner_networkscanningsessionipaddress.is_up == 'down' {search_where_clause} group by network_scanner_networkscanningsessionipaddress.id
                """
                )

            elif request.GET.get('filter_input') == 'not-scanned':
                ip_addresses_list = NetworkScanningSessionIPAddress.objects.raw(
                f"""
                    SELECT network_scanner_networkscanningsession.*, network_scanner_networkscanningsessionipaddress.id AS networkscanningsessionipaddress_id, network_scanner_networkscanningsessionipaddress.ip_address, network_scanner_networkscanningsessionipaddress.is_up,
                    network_scanner_DeviceAndOSDetail.*
                    from network_scanner_networkscanningsession
                    LEFT JOIN
                    network_scanner_networkscanningsessionipaddress on network_scanner_networkscanningsession.id == network_scanner_networkscanningsessionipaddress.related_scan_session_id
                    LEFT JOIN
                    network_scanner_DeviceAndOSDetail on network_scanner_networkscanningsessionipaddress.id == network_scanner_DeviceAndOSDetail.related_ip_address_id
                    where network_scanner_networkscanningsession.id == {network_scanning_session_obj.pk} and network_scanner_networkscanningsessionipaddress.is_up == 'ns' {search_where_clause} group by network_scanner_networkscanningsessionipaddress.id
                """
                )

            else:
                ip_addresses_list = list()
        else:
            ip_addresses_list = NetworkScanningSessionIPAddress.objects.raw(
            f"""
                SELECT network_scanner_networkscanningsession.*, network_scanner_networkscanningsessionipaddress.id AS networkscanningsessionipaddress_id, network_scanner_networkscanningsessionipaddress.ip_address, network_scanner_networkscanningsessionipaddress.is_up,
                network_scanner_DeviceAndOSDetail.*
                from network_scanner_networkscanningsession
                LEFT JOIN
                network_scanner_networkscanningsessionipaddress on network_scanner_networkscanningsession.id == network_scanner_networkscanningsessionipaddress.related_scan_session_id
                LEFT JOIN
                network_scanner_DeviceAndOSDetail on network_scanner_networkscanningsessionipaddress.id == network_scanner_DeviceAndOSDetail.related_ip_address_id
                where network_scanner_networkscanningsession.id == {network_scanning_session_obj.pk} {search_where_clause} group by network_scanner_networkscanningsessionipaddress.id
            """
            )

            # ['id', 'scanning_session_name', 'base_ip_address', 'ip_range', 'random_or_not', 'creation_date', 'ip_address', 'is_up', 'port_numbers', 'is_opens']
            # print(ip_addresses_list.columns)

        if request.GET.get('filter_input') in ['all', 'scanned', 'not-scanned', 'up', 'down']:
            paginator_obj = Paginator(ip_addresses_list, 250)

            page_number = request.GET.get('page')
            try:
                selected_page = paginator_obj.get_page(page_number)
            except PageNotAnInteger:
                selected_page = paginator_obj.get_page(1)
            except EmptyPage:
                selected_page = paginator_obj.get_page(page_number)
        else:
            selected_page = ip_addresses_list


        data = {
            "object": network_scanning_session_obj,
            "number_of_ip_addresses": len(ip_addresses_list),
            "ip_address_selected_page_list": selected_page,
            "is_scanned": IS_SCANNED,
            "network_device_scanning_form": form,
            "filter_input": request.GET.get('filter_input')
        }
        return render(request, self.template_name, data)





class NetworkScanningSessionRemoveDownServer(FormView):
    form_class = NetworkScanningSessionDownServersDeletionForm
    template_name = 'down-server-delete-page.html'

    def get_success_url(self):
        return reverse_lazy('session-detail', kwargs={'pk': self.kwargs.get('pk')})



    def form_valid(self, form):
        scanning_session_pk = get_object_or_404(NetworkScanningSession, pk=self.kwargs.get('pk')).pk
        
        with connection.cursor() as cursor:
            cursor.execute(
                            f"""
                            DELETE from network_scanner_portstatus where related_ip_address_id in
                            (SELECT id from network_scanner_networkscanningsessionipaddress where related_scan_session_id == {scanning_session_pk} and is_up == 'down')            
                            """
                        )

            cursor.execute(
                            f"""
                            DELETE from network_scanner_deviceandosdetail where related_ip_address_id in
                            (SELECT id from network_scanner_networkscanningsessionipaddress where related_scan_session_id == {scanning_session_pk} and is_up == 'down')            
                            """
                        )
        
            cursor.execute(
                            f"""
                            DELETE from network_scanner_networkscanningsessionipaddress where related_scan_session_id == {scanning_session_pk} and is_up == 'down'
                            """
                        )
        return super().form_valid(form)