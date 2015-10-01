#!/usr/bin/python
# -*- coding: utf-8 -*-
import base64

try:
    from xml.etree import cElementTree as etree
except ImportError:
    from xml.etree import ElementTree as etree

from openvas_lib import *
from openvas_lib.common import *
from openvas_lib.ompv5 import OMPv5

__all__ = ["OMPv6"]


class OMPv6(OMPv5):
    def get_tasks_progress(self, task_id):
        """
        Get the progress of the task.

        :param task_id: ID of the task
        :type task_id: str

        :return: a float number between 0-100
        :rtype: float

        :raises: ClientError, ServerError
        """
        if not isinstance(task_id, basestring):
            raise TypeError("Expected string, got %r instead" % type(task_id))

        # Get status with xpath
        tasks = self.get_tasks()
        status = tasks.find('.//task[@id="%s"]/status' % task_id)

        if status is None:
            raise ServerError("Task not found")

        if status.text in ("Running", "Pause Requested", "Paused"):
            progress = tasks.findall('.//task[@id="%s"]/progress' % task_id)
            if progress:
                return float(progress[0].text)
        return 100.0  # Task finished

        try:
            return m_sum_progress/m_progress_len
        except ZeroDivisionError:
            return 0.0

    @property
    def get_scanners(self):
        """
        Rerturn scanner id
        """
        request = "<get_scanners />"
        scanners = self._manager.make_xml_request(request, xml_result=True)
        return [scanner.attrib.get('id') for scanner in scanners.findall('scanner')]

    def create_task(self, name, target, config=None, comment="", scanner=None):
        """
        Creates a task in OpenVAS.

        :param name: name to the task
        :type name: str

        :param target: target to scan
        :type target: str

        :param config: config (profile) name
        :type config: str

        :param comment: comment to add to task
        :type comment: str

        :return: the ID of the task created.
        :rtype: str

        :raises: ClientError, ServerError
        """

        if not config:
            config = "Full and fast"

        if not scanner:
            scanner = self.get_scanners[0]

        request = '''
        <create_task>
           <name>{name}</name>
           <comment>{comment}</comment>
           <config id="{config}"/>
           <target id="{target}"/>
           <scanner id="{scanner}"/>
        </create_task>
        '''.format(name=name, comment=comment, config=config, target=target, scanner=scanner)
        return self._manager.make_xml_request(request, xml_result=True).get("id")

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
