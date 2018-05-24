#!/usr/bin/python
# -*- coding: utf-8 -*-


from openvas_lib import *
from openvas_lib.common import *
from openvas_lib.ompv6 import OMPv6

__all__ = ["OMPv7"]


class OMPv7(OMPv6):
    @property
    def default_scanner(self):
        """
        Rerturn scanner id
        """
        request = "<get_scanners />"
        scanners = self._manager.make_xml_request(request, xml_result=True)
        return [scanner.attrib.get('id') for scanner in scanners.findall('scanner') if scanner.find('name').text == 'OpenVAS Default'][0]

    def get_port_list(self, name=None):
        if not name:
            name = 'All TCP and Nmap 5.51 top 100 UDP'
        request = '<get_port_lists />'
        port_lists = self._manager.make_xml_request(request, xml_result=True)
        for i in port_lists.findall('port_list'):
            if i.find('name').text == name:
                return i.get('id')
        return port_lists.findall('port_list')[0].get('id')
