#!/usr/bin/env python
# coding=utf-8

import threading
import time as _time
import global_variable as gv
from wp_probe_api import weak_probe_handler_api
from cyberlib_my_print import print_ip
from cyberlib_log_stdout import StdOutLog

LOGLEVEL = gv.GLOBAL_LEVEL['wp_process']

class WeakProbeProcess(threading.Thread):

    def __init__(self, ip_json_array):
        threading.Thread.__init__(self)
        self.ip_json_array = ip_json_array
        self._stop = False
        self.logger = StdOutLog(LOGLEVEL)

    # The function must have
    def run(self):
        for ip_json in self.ip_json_array:
            if self._stop:
                break
            weak_probe_handler_api(ip_json)
            self.logger.debug('wp_process: success finished the weak password probe', "[WeakpasswordProber]" + str(ip_json['ip']) )
            _time.sleep(1)
        # 再也没有数据

    # The function must have
    def stop(self):
        """设置线程结束标识
        :return:
                无
        """
        self._stop = True

    # The function must have
    def print_scan(self):
        # output the ip_json_list to the output
        for ip_json in self.ip_json_array:
            print_ip(ip_json)


    # The function must have
    def is_running(self):
        """
        :return: thread.isAlive(): 判断线程是否活着
        """
        return self.isAlive()

