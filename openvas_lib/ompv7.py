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
