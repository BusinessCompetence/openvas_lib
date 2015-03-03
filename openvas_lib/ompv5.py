#!/usr/bin/python
# -*- coding: utf-8 -*-
import base64

try:
    from xml.etree import cElementTree as etree
except ImportError:
    from xml.etree import ElementTree as etree

from openvas_lib import *
from openvas_lib.common import *
from openvas_lib.ompv4 import OMPv4

__all__ = ["OMPv5"]


class OMPv5(OMPv4):
    REPORT_EXTENSIONS = ['xml', 'html', 'csv', 'tex', 'nbe', 'pdf', 'svg', 'txt', 'vna']

    def get_task(self, task_id=None, id_only=False):
        if not task_id:
            body_request = '<get_tasks/>'
        else:
            body_request = '<get_tasks task_id="%s" details="1" />' % task_id
        try:
            m_response = self._manager.make_xml_request(body_request, xml_result=True)
        except ServerError, e:
            raise VulnscanServerError("Can't get the xml for the task %s. Error: %s" % (task_id, e.message))
        if task_id:
            return m_response.find('task')
        if id_only:
            return [i.get('id') for i in m_response.findall('task')]
        return m_response

    def get_report_by_task(self, task_id, report_format='xml'):
        if report_format not in self.REPORT_EXTENSIONS:
            raise Exception("Invalid report format, got '%s' but available %s" % (report_format, self.REPORT_EXTENSIONS))
        task = self.get_task(task_id)
        report_id = task.find('last_report').find('report').get('id')
        report_formats = self.get_report_formats()
        return self.get_report_by_format(report_id, report_formats[report_format])

    def get_report_xml(self, report_id):
        report_formats = self.get_report_formats()
        return self.get_report_by_format(report_id, report_formats['xml'])

    def get_report_by_format(self, report_id, format_id):
        if not isinstance(report_id, basestring):
            raise TypeError("Expected string, got %r instead" % type(report_id))
        if not isinstance(format_id, basestring):
            raise TypeError("Expected string, got %r instead" % type(format_id))
        try:
            m_response = self._manager.make_xml_request('<get_reports report_id="%s" format_id="%s" />' % (report_id, format_id), xml_result=True)
        except ServerError, e:
            raise VulnscanServerError("Can't get the xml for the report_format %s. Error: %s" % (report_id, e.message))
        return m_response

    def get_report_formats(self, report_format_id=None):
        if report_format_id and not isinstance(report_format_id, basestring):
            raise TypeError("Expected string, got %r instead" % type(report_format_id))
        try:
            body_request = '<get_report_formats '
            if report_format_id:
                body_request += 'report_format_id="%s"'.format(report_format_id)
            body_request += ' />'
            m_response = self._manager.make_xml_request(body_request, xml_result=True)
        except ServerError, e:
            raise VulnscanServerError("Can't get the xml for the report%s. Error: %s" % (report_format_id, e.message))
        report_formats = {}
        for i in m_response.findall('report_format'):
            report_formats[i.find('extension').text] = i.get('id')
        return report_formats

    def get_profiles(self, profile_id=None, detail=False):
        if profile_id and not isinstance(profile_id, basestring):
            raise TypeError("Expected string, got %r instead" % type(profile_id))
        try:
            if profile_id:
                detail = 'preferences="1" families="1" tasks="1"' if detail else ''
                body_request = '<get_configs config_id="%s" %s/>' % (profile_id, detail)
            else:
                body_request = '<get_configs/>'
            return self._manager.make_xml_request(body_request, xml_result=True)
        except ServerError, e:
            raise VulnscanServerError("Can't get the xml for the profiles. Error: %s" % e.message)

    def get_nvt(self, nvt_oid):
        if nvt_oid and not isinstance(nvt_oid, basestring):
            raise TypeError("Expected string, got %r instead" % type(nvt_oid))
        try:
            body_request = '<get_nvts nvt_oid="%s" details="1" preferences="1"/>' % nvt_oid
            return self._manager.make_xml_request(body_request, xml_result=True)
        except ServerError, e:
            raise VulnscanServerError("Can't get the xml for the profiles. Error: %s" % e.message)

    def get_nvt_families(self):
        try:
            return self._manager.make_xml_request('<get_nvt_families/>', xml_result=True)
        except ServerError, e:
            raise VulnscanServerError("Can't get the xml for the profiles. Error: %s" % e.message)

    def edit_profile(self, config_id, nvt_selection_list=[], preference=[]):
        if config_id and not isinstance(config_id, basestring):
            raise TypeError("Expected string, got %r instead" % type(config_id))

        config = self.get_configs(config_id)
        config_name = config.find('config').find('name').text

        for nvt in nvt_selection_list:
            if nvt and not isinstance(nvt, basestring):
                raise TypeError("Expected string, got %r instead in nvt_selection_list" % type(nvt))

        body_request = '<modify_config config_id="%s">' % config_id
        if len(nvt_selection_list):
            body_request += '<nvt_selection>'
            body_request += '<family>%s</family>' % config_name
            for nvt in nvt_selection_list:
                body_request += '<nvt oid="%s"/>' % nvt
            body_request += '</nvt_selection>'
        elif len(preference):
            allowed_types = ['checkbox', 'radio', 'entry']
            for item in preference:
                if item.get('type') not in allowed_types:
                    raise TypeError("Incorrect name of the property, got '%s', expected one of: " % allowed_types)
                body_request += '<preference><nvt oid="%s"/><name>%s[%s]:%s</name><value>%s</value></preference>' % (
                    item.get('oid'),
                    item.get('name'),
                    item.get('type'),
                    item.get('property_name'),
                    base64.b64encode(item.get('value')),
                )
        body_request += '</modify_config>'
        try:
            return self._manager.make_xml_request(body_request, xml_result=True)
        except ServerError, e:
            raise VulnscanServerError("Can't get the xml for the profiles. Error: %s" % e.message)

    def create_config(self, config_id):
        if config_id and not isinstance(config_id, basestring):
            raise TypeError("Expected string, got %r instead" % type(config_id))
        body_request = '<create_config><copy>%s</copy></create_config>' % config_id
        try:
            m_response = self._manager.make_xml_request(body_request, xml_result=True)
            return m_response.get('id')
        except ServerError, e:
            raise VulnscanServerError("Can't create the configuration. Error: %s" % e.message)

