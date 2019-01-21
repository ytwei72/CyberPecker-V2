# -*- coding:utf-8 -*-
"""
    ID: scan_process.py
    Date: 2016/07/21
    Subject: 扫描进程类基类
"""


import sys as _sys
import time as _time

from libnmap.process import NmapProcess
from libnmap.parser import NmapParser
from libnmap.parser import NmapParserException

import global_variable as _global
from cyberlib_const_parser import Config
from cyberlib_my_print import *
from cyberlib_log_stdout import StdOutLog
from cyberlib_error import *


__LOG_LEVEL__ = _global.GLOBAL_LOG_LEVEL['scan_process']


class ScanProcess(object):
    """
    """
    def __init__(self, targets):
        """

        :param targets: hosts to be scanned. Could be a string of hosts \
        separated with a coma or a python list of hosts/ip.
        :type targets: string or list

        :return:
        """
        self.logger = StdOutLog(__LOG_LEVEL__)
        self.config = Config(_global.CONFIG_DIR+'/const.ini', 'ScanProcess')

        self.targets = targets

        ##
        # custom attributes: const_options
        ##
        if self.config.isvalid:
            self.const_options = self.config.get('const_options')
        else:
            self.const_options = ''

        self.options_str = ''

        # init an NmapProcess instance as a member variable
        self.nmproc = NmapProcess()

    def set_options(self, string_options_from_parsing):
        """

        :param string_options_from_parsing:
        :type string_options_from_parsing: str
        :return:
        """
        self.options_str = ' '+self.const_options + string_options_from_parsing
        self.logger.print_debug("[HDScanProcess]options: {0}".format(self.options_str))

    def run(self):
        """后台启动nmap进程

        :return: return code from nmap execution
        """
        # set the options to run a new nmap subprocess
        self.set_options(_global.OPTIONS)
        # recreate an NmapProcess instance
        self.nmproc = NmapProcess(targets=self.targets, options=self.options_str, safe_mode=False)
        self.logger.print_debug("[HDScanProcess]nmap:command>>", self.command_line)
        rc = self.nmproc.sudo_run_background()

        return rc

    def start(self):
        """多线程调用时使用的方法，调用run方法

        :return:
        """
        self.run()

    def is_running(self):
        """检查nmap是否正在运行

        :return: True if nmap is still running
        :rtype: bool
        """
        return self.nmproc.is_running()

    def stop(self):
        """停止nmap进程
        """
        self.nmproc.stop()

    def print_scan(self):
        """打印nmap扫描结果

        :return : number of error ip or 0
        :rtype: int
        """
        # todo: add subclass' method implementations in the following
        try:
            parsed = NmapParser.parse(self.nmproc.stdout)
            self._print_scan(parsed)
            return 0
        except NmapParserException as e:
            self.logger.print_info("[MultiScanController]Exception raised while parsing scan:{0}".format(e.msg))
            print_error(RESULT_PARSE_ERROR, '{0}'.format(e.msg))
            error_number = len(self.targets)
            self.logger.print_debug("[MultiScanController]parse error")
            return error_number

    def _print_scan(self, nmap_report):
        pass

    @property
    def command_line(self):
        """返回nmap进程的运行命令
        注意： 在sudo_run_background()运行后才能返回正确的命令

        ：return： command string
        """
        return self.nmproc.get_command_line()

    @property
    def progress(self):
        """返回nmap进程的扫描进度

        :return: percentage of job processed.
        """
        return self.nmproc.progress

    @property
    def elapsed(self):
        """返回扫描进程已经运行了多长时间（以秒为单位）

        :return: string
        """
        return self.nmproc.elapsed

    @property
    def starttime(self):
        """返回扫描进程的开始时间 格式为Unix 时间戳

        :return: string. Unix timestamp
        """
        return self.nmproc.starttime

    @property
    def targets_size(self):
        """返回扫描进程要扫描ip的个数

        :return: list of string
        """
        return len(self.nmproc.targets)

    @property
    def current_task(self):
        """返回当前扫描进程正在进行的扫描任务

        :return: NmapTask or None if no task started yet
        """
        return self.nmproc.current_task
