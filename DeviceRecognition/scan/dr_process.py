#!/usr/bin/env python
#-*- coding:utf-8 -*-
"""
    ID: dr_process.py
    Date: 2016/07/22
    Subject: 设备识别处理类
    Author: Achelics
    Update: 2016/10/30
"""

from threading import Thread

from cyberlib_my_print import print_ip
from dr_api import dr_handler

class DRProcess(Thread):

    def __init__(self, ip_json_array):
        Thread.__init__(self)
        self.ip_json_array = ip_json_array
        self._stop = False

    # running the drprocess, must have
    def run(self):
        for ip_json in self.ip_json_array:
            if self._stop:
                break
            # start the device recognition
            dr_handler(ip_json)

    # stop the thread function, must have
    def stop(self):
        self._stop = True

    # output to the std out, must have
    def print_scan(self):
        # output the ip_json to the output
        for ip_json in self.ip_json_array:
            print_ip(ip_json)

    # Juge the thread whether alive, must have
    def is_running(self):
        return self.isAlive()
