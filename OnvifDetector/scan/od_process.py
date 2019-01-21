# -*- coding:utf-8 -*-
"""
    ID: od_process.py
    Subject: 实现onvif协议的探测
    Date: 2016/08/31
"""
__author__ = 'achelics'
from threading import Thread
from onvif_detect_api import onvif_detect_api
from cyberlib_my_print import print_ip

class ODProcess(Thread):
    def __init__(self, ip_json_array):
        Thread.__init__(self)
        self._stop = False
        self.ip_json_array = ip_json_array

    def run(self):
        if self._stop:
            return
        onvif_detect_api(self.ip_json_array)

    # stop the thread function, must have
    def stop(self):
        self._stop = True

    def is_running(self):
        return self.isAlive()

    def print_scan(self):
        for ip_json in self.ip_json_array:
            print_ip(ip_json)