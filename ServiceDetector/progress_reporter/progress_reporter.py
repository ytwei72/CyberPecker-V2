# -*- coding:utf-8 -*-
"""
    ID : progress_reporter.py
    Date： 2016/08/15
    Subject : 获取任务进度，并打印到标准输出
    说明： 不同于主机发现，服务探测 的进度报告仅用于调试
"""

import sys as _sys
import time as _time
from threading import Thread

import global_variable as _global

from cyberlib_my_print import *
from cyberlib_log_stdout import StdOutLog

__LOG_LEVEL__ = _global.GLOBAL_LOG_LEVEL['progress_reporter']


class ProgressReporter(Thread):
    """

    """
    def __init__(self, ms_manager=None):
        """ProgressReporter类的构造方法

        :param ms_manager: MultiScanManager instance if the param is not None
        :type ms_manager: MultiScanManager or None
        :return:
        """
        Thread.__init__(self)
        self.debug = __LOG_LEVEL__
        self.logger = StdOutLog(self.debug)

        self.ms_manager = ms_manager

        # reference time
        self.zero_t = _time.mktime(_time.strptime("00:00:00", "%H:%M:%S"))
        # start time
        self.start_time = _time.time()
        self.is_continue = True

    def run(self):
        print_cycle = 1
        print_interval = 3
        while self.is_continue:
            # print debug info once every 5 cycles
            print_cycle = (print_cycle + 1) % print_interval

            current_time = _time.time()

            self.report_subprocess(print_cycle)

            time_cost = self.zero_t+current_time-self.start_time
            # _time.strftime('%H:%M:%S',_time.localtime(time_cost))
            self.logger.print_info('[ProgressReporter]Status {0}  '.format(_time.strftime('%H:%M:%S', _time.localtime(time_cost))))

            _time.sleep(2)

    def report_subprocess(self, print_cycle):
        """报告扫描子进程的进度
        该信息为调试信息, 如果 self.debug 为True, 则打印信息, 否则不打印

        :param print_cycle: print info if print_cycle is 0
        :type print_cycle: int
        :return:
        """
        # no print
        if not self.debug or print_cycle:
            return

        self._print_status_info(self._get_process_status(),
                                _time.time())

    def _get_process_status(self):
        """获取MultiScanController 中正在运行的扫描进程的状态信息

        :return: list of subprocess status
        :rtype: list
        """
        status_list = []
        if self.ms_manager:
            for running_scan in self.ms_manager.running_scan_list:
                scanproc, scanid = running_scan
                ts = scanproc.targets_size
                ntask = scanproc.current_task
                status_list.append((scanid, ts, ntask,
                                    scanproc.starttime,
                                    scanproc.progress))
        else:
            pass
        # end if

        return status_list

    def _print_status_info(self, status_list, current_time):
        """根据扫描子进程状态列表 打印状态信息

        :param status_list: list of subprocess status
        :type status_list: list

        :param current_time:
        :type current_time: string. Unix timestamp

        :return:
        """
        sl = status_list
        ct = current_time
        if sl:
            for status in status_list:
                scanid, target_size, ntask, starttime, progress = status
                elapsed = _time.strftime('%M:%S', _time.localtime(int(ct)-int(starttime)))
                if ntask:
                    info = "[ProgressReporter]No.{0} scan:{1} task: {2} ({3}) lasts: {4} ，DONE: {5}%".format(scanid,
                                                                                                             target_size,
                                                                                                             ntask.name,
                                                                                                             ntask.status,
                                                                                                             elapsed,
                                                                                                             progress)
                else:
                    info = "[ProgressReporter]No.{0} scan:{1} lasts: {2} ，DONE: {3}%".format(scanid,
                                                                                             target_size,
                                                                                             elapsed,
                                                                                             progress)
                self.logger.print_info(info)
        # else pass

    def stop(self):
        self.is_continue = False
