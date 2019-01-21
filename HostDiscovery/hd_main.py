#!/usr/bin/env python
# -*- coding:utf-8 -*-
__AUTHOR__ = 'CR'

"""
    ID: HD_main.py
    Date: 2016/07/15
    Subject: HostDiscovery main
"""

import os as _os
import time as _time
import sys as _sys

import global_variable as _global
from cyberlib_my_print import *
from cyberlib_multi_scan_manager import MultiScanManager
from cyberlib_std_input import StdInputHandler
from cyberlib_log_stdout import StdOutLog
from cyberlib_error import PERMISSION_DENIED_ERROR

from scan import HDProcess
from progress_reporter import ProgressReporter
from tools import CMDParser


__LOG_LEVEL__ = _global.GLOBAL_LOG_LEVEL['HD_main']


class HostDiscovery:
    """主机发现类
       use following global variables：
                        IPJsonQueue
                        CONFIG_DIR
                        OPTIONS
    """
    def __init__(self, *args, **kwargs):
        self.logger = StdOutLog(__LOG_LEVEL__)

        # 命令行解析类
        self.cmd_parser = CMDParser()
        # 多任务扫描管理类
        self.MSM = None
        # 进度报告类
        self.PR = None
        # 标准输入流处理类
        self.StdIH = None

        self.opt_str = ''

    def parse_cmd(self):
        """parse cmd

        :return:
        """
        self.logger.print_debug("[HostDiscovery]cmd parse>>")
        self.cmd_parser.parse()
        self.opt_str = ''.join(self.cmd_parser.init_args())

        # decompose ip from command's parsering
        iplist = self.cmd_parser.decomepose_ip()
        # ip enqueue
        num = _global.IP_JSON_QUEUE.put(iplist)
        # set ip_queue's end_flag
        _global.IP_JSON_QUEUE.set_enqueue_end()

        _global.OPTIONS = self.opt_str

        self.logger.print_debug("[HostDiscovery]", self.opt_str)
        self.logger.print_debug("[HDScanProcess]OPTIONS: ", _global.OPTIONS)
        self.logger.print_debug("[HostDiscovery]", _global.IP_JSON_QUEUE.qsize())
        self.logger.print_debug("[HostDiscovery] {0} IP enqueued...".format(num))


def user_check():
    """检查程序是否以超级用户身份运行

    :return:
    """
    import getpass
    import pwd
    user = getpass.getuser()
    uid = pwd.getpwnam(user).pw_uid
    if uid is not 0:
        print_error(PERMISSION_DENIED_ERROR, ': {0}'.format(user))
        exit(0)





def main():
    """程序执行主函数

    主要线程按如下顺序启动：
                  1.MSC(多任务扫描控制主线程)
                  2.PR (进度报告主线程)
                  3.StdIH(标准输入流处理函数)
    """
    reload(_sys)
    _sys.setdefaultencoding('utf-8')

    # main_dir = _os.path.dirname(_os.path.realpath(__file__))
    # config_dir = _os.path.join(main_dir, "config")
    HD = HostDiscovery()
    HD.parse_cmd()

    HD.MSM = MultiScanManager(scan_process=HDProcess,
                              queue=_global.IP_JSON_QUEUE,
                              config_path=_global.CONFIG_DIR,
                              config_name='const.ini')
    HD.MSM.setDaemon(True)
    # 多任务扫描控制线程启动
    HD.MSM.start()

    HD.PR = ProgressReporter(ms_manager=HD.MSM)
    HD.PR.setDaemon(True)

    HD.StdIH = StdInputHandler(queue=_global.IP_JSON_QUEUE,
                               ms_manager=HD.MSM)
    HD.StdIH.setDaemon(True)

    # 进度报告线程启动
    HD.PR.start()

    # 标准输入流处理线程启动
    HD.StdIH.start()

    # 阻塞等待多任务扫描管理线程结束
    while True:
        try:
            # 判断多任务扫描控制线程是否结束
            if HD.MSM.isAlive():
                _time.sleep(6)
                continue
            # 如果结束,终止其他线程
            else:
                _time.sleep(2)
                # 终止进度报告线程
                HD.PR.stop()
                _time.sleep(1)
                # 终止标准输入流处理线程
                HD.StdIH.stop()
                break
            # end if
        # 响应ctrl^c 终止所有线程 退出
        except KeyboardInterrupt:
            HD.logger.print_info('Keyboard Interruption, exit...')
            HD.MSM.stop()
            break
        # end while

    print_end()
    _os.system('stty sane')


if __name__ == '__main__':
    user_check()
    main()
