# -*- coding:utf-8 -*-

"""
    ID: od_main.py
    Subkect: onvif协议的入口
    Date: 2016/08/31
"""
__author__ = 'achelics'

import sys as _sys
import time as _time
import os as _os
import argparse

import global_variable as _gv
from cyberlib_multi_scan_manager import MultiScanManager
from cyberlib_my_print import *
from cyberlib_std_input import StdInputHandler
from cyberlib_cmd_parser import CMDConfig
from onvif_detect_api import onvif_detect_init

from progress_reporter import ProgressReporter

from scan import od_process

if __name__ == '__main__':
    reload(_sys)
    _sys.setdefaultencoding('utf-8')

    #add the logs director
    mkdir_match = 'mkdir -p ' + _gv.LOGS_DIR
    if _os.path.exists(_gv.LOGS_DIR) is False:
        _os.system(mkdir_match)
    # get the commend args
    result_args = CMDConfig(_gv.CONFIG_DIR + '/cmd_arg.ini').get_parser().parse_args()
    project_name = result_args.project_name
    task_id = result_args.task_id

    config_path = _os.path.join(_gv.CONFIG_DIR, 'od_func.ini')
    # init the onvif dector
    onvif_detect_init(config_path, project_name)

    # Start the multi_thread block
    MSM = MultiScanManager(od_process.ODProcess, _gv.IP_JSON_QUEUE, _gv.CONFIG_DIR, 'const.ini')
    MSM.setDaemon(True)
    MSM.start()

    PR = ProgressReporter()
    PR.setDaemon(True)
    # 启动进度报告模块
    PR.start()

    # Start the std input block
    STH = StdInputHandler(_gv.IP_JSON_QUEUE, MSM)
    STH.setDaemon(True)
    STH.start()

    # Block and wait the mutil_thread stop
    while True:
        try:
            # Juge the mutil_thread state
            if MSM.isAlive():
                _time.sleep(3)
                continue
            # If finished, stop thread.
            else:
                _time.sleep(2)
                PR.stop()
                _time.sleep(2)
                STH.stop()
                break
        # Ctrl^C, stop all thread.
        except KeyboardInterrupt:
            MSM.stop()
            break

    print_end()
