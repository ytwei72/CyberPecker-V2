#!/usr/bin/env python
# coding=utf-8
import os as _os
import sys as _sys
import time as _time

import global_variable as _gv
from progress_reporter import ProgressReporter
from scan import wp_process

from cyberlib_cmd_parser import CMDConfig
from cyberlib_std_input import StdInputHandler
from cyberlib_multi_scan_manager import MultiScanManager
from cyberlib_my_print import print_end
from cyberlib_log_stdout import StdOutLog
from wp_probe_api import wp_probe_init

LOG_LEVEL = _gv.GLOBAL_LEVEL['wp_main']
__logger = StdOutLog(LOG_LEVEL)

# 主函数
if __name__ == '__main__':
    reload(_sys)
    _sys.setdefaultencoding('utf-8')

    # 初始化弱口令配置信息
    cmd_arg = _os.path.join(_gv.CONFIG_DIR, 'cmd_arg.ini')
    wp_func_file = _os.path.join(_gv.CONFIG_DIR, 'wp_func.ini')
    rtsp_config_file = _os.path.join(_gv.CONFIG_DIR, "rtsp_url_map.ini")
    http_config_file = _os.path.join(_gv.CONFIG_DIR, "http_url_map.ini")
    protocol_default_username = _os.path.join(_gv.CONFIG_DIR, "protocol_default_username.ini")

    # get the commend args
    result_args = CMDConfig(cmd_arg).get_parser().parse_args()
    execute_module = ""
    if result_args.probe_module:
        execute_module = result_args.probe_module

    # 弱口令功能初始化
    wp_probe_init(wp_func_config=wp_func_file, commend_args=execute_module, rtsp_config_file=rtsp_config_file,
                  http_config_file=http_config_file, protocol_username_file=protocol_default_username)


    MSM = MultiScanManager(wp_process.WeakProbeProcess, _gv.IP_JSON_QUEUE, _gv.CONFIG_DIR, "const.ini")
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
                _time.sleep(1)
                STH.stop()
                break
            # end if
        # 响应 ctrl^c 终止所有线程 退出
        except KeyboardInterrupt:
            __logger.info('Keyboard Interruption, exit...', '[WeakPasswordProbe]')
            MSM.stop()
            break

    print_end()
