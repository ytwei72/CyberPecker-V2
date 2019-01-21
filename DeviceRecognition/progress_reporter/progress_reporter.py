# -*- coding:utf-8 -*-
"""
    进度报告模块（暂时只报告时间）
"""

import time as _time
from threading import Thread
import global_variable as _gv
from cyberlib_log_stdout import StdOutLog

LOG_LEVEL = _gv.GLOBAL_LOG_LEVEL['progress_reporter']

class ProgressReporter(Thread):
    """

    """
    def __init__(self, ms_manager=None):
        """ProgressReporter 类的构造方法

        :param ms_manager: MultiScanManager instance if the param is not None
        :type ms_manager: MultiScanManager or None
        :return:
        """
        Thread.__init__(self)
        self.logger = StdOutLog(LOG_LEVEL)

        self.ms_manager = ms_manager

        self.is_continue = True
        # reference time
        self.zero_t = _time.mktime(_time.strptime("00:00:00","%H:%M:%S"))
        # start time
        self.start_time = _time.time()

    def run(self):
        while self.is_continue:
            current_time = _time.time()
            time_cost = self.zero_t + current_time - self.start_time
            self.logger.info('Status {0}'.format(_time.strftime('%H:%M:%S', _time.localtime(time_cost))), "[ProgressReporter]")

            _time.sleep(2)

    def stop(self):
        self.is_continue = False
