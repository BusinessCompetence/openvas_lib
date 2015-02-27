#!/usr/bin/python
# -*- coding: utf-8 -*-

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

    def get_profiles(self, profile_id=None):
        if profile_id and not isinstance(profile_id, basestring):
            raise TypeError("Expected string, got %r instead" % type(profile_id))
        try:
            if profile_id:
                body_request = '<get_configs config_id="%s"/>' % profile_id
            else:
                body_request = '<get_configs/>'
            m_response = self._manager.make_xml_request(body_request, xml_result=True)
            return m_response
        except ServerError, e:
            raise VulnscanServerError("Can't get the xml for the profiles. Error: %s" % e.message)
