#!/usr/bin/env python
#-*- coding:utf-8 -*-

import argparse
import sys as _sys
import time as _time
import os as _os
import global_variable as _gv
from progress_reporter import ProgressReporter

from cyberlib_std_input import StdInputHandler
from cyberlib_multi_scan_manager import MultiScanManager
from cyberlib_my_print import print_end
from cyberlib_cmd_parser import CMDConfig
from cyberlib_log_stdout import StdOutLog
from scan.dr_process import DRProcess
from dr_api import init_dr_config

__LOG_LEVEL_ = _gv.GLOBAL_LOG_LEVEL['dr_main']
__logger = StdOutLog(__LOG_LEVEL_)

if __name__ == '__main__':
    reload(_sys)
    _sys.setdefaultencoding('utf-8')

    # get the commend args
    result_args = CMDConfig(_gv.CONFIG_DIR + '/cmd_arg.ini').get_parser().parse_args()
    project_name = result_args.project_name
    task_id = result_args.task_id
    project_id = project_name + '_' + str(task_id)

    func_file = _os.path.join(_gv.CONFIG_DIR, 'dr_fun.ini')
    # init the device recognition config
    init_dr_config(func_file, project_id=project_id)

    MSM = MultiScanManager(DRProcess, _gv.IP_JSON_QUEUE, _gv.CONFIG_DIR, 'const.ini')
    MSM.setDaemon(True)
    # 启动多线程模块
    MSM.start()

    PR = ProgressReporter()
    PR.setDaemon(True)
    # 启动进度报告模块
    PR.start()

    STH = StdInputHandler(_gv.IP_JSON_QUEUE, MSM)
    STH.setDaemon(True)
    # 启动标准输入流模块
    STH.start()

    # 阻塞等待多任务扫描管理线程结束

    while True:
        try:
            # 判断多任务扫描控制线程是否结束
            if MSM.isAlive():
                _time.sleep(3)
                continue
            # 如果结束,终止其他线程
            else:
                _time.sleep(2)
                PR.stop()
                _time.sleep(2)
                STH.stop()
                break
                # end if
        # 响应 ctrl^c 终止所有线程 退出
        except KeyboardInterrupt:
            __logger.info('Keyboard Interruption, exit...', '[DeviceRecognition]')
            MSM.stop()
            break

    print_end()
