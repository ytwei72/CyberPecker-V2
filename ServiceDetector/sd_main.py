#!/usr/bin/env python
# -*- coding:utf-8 -*-
__AUTHOR__ = 'CR'



"""
    ID: ps_main.py
    Date: 2016/07/15
    Subject: Service Detection main
"""

import os  as _os
import time as _time
import sys as _sys

import global_variable as _global

from cyberlib_my_print import *
from cyberlib_multi_scan_manager import MultiScanManager
from cyberlib_std_input import StdInputHandler
from cyberlib_log_stdout import StdOutLog
from cyberlib_error import PERMISSION_DENIED_ERROR

from progress_reporter import ProgressReporter
from scan import PSPrcoess
from tools import CMDParser


__LOG_LEVEL__ = _global.GLOBAL_LOG_LEVEL['sd_main']


class PortScan:
    """

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
        self.logger.print_debug("[PortScan]cmd parse>>")
        self.cmd_parser.parse()
        self.opt_str = ''.join(self.cmd_parser.init_args())

        # decomepose ip from command's parsering
        iplist = self.cmd_parser.decomepose_ip()
        if iplist:
            # ip enqueue
            num = _global.IP_JSON_QUEUE.put(iplist)
            # set ip_queue's end flag
            # TODO：comment out set_enqueue_end() if PortScan software is called as a child software
            _global.IP_JSON_QUEUE.set_enqueue_end()
            self.logger.print_debug("[PortScan]ip enqueue end_flag has been set")
            self.logger.print_debug("[PortScan]{0} IP enqueued...".format(num))
            # self.logger.print_debug("[PortScan]",global_variable.IP_JSON_QUEUE.qsize())

        _global.OPTIONS = self.opt_str
        self.logger.print_debug("[PortScan]>>", _global.OPTIONS)

    @staticmethod
    def _clean_oldlog():
        """清理可能存在的旧日志"""
        log_file = ['MSC.log.txt',
                    'portScanPy.log.txt']

        for log in log_file:
            if _os.path.exists(log):
                _os.remove(log)


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

    PS = PortScan()
    PS.parse_cmd()
    PS._clean_oldlog()

    PS.MSM = MultiScanManager(scan_process=PSPrcoess,
                              queue=_global.IP_JSON_QUEUE,
                              config_path=_global.CONFIG_DIR,
                              config_name='const.ini')
    PS.MSM.setDaemon(True)
    # 多任务扫描控制线程启动
    PS.MSM.start()

    PS.PR = ProgressReporter(ms_manager=PS.MSM)
    PS.PR.setDaemon(True)

    PS.StdIH = StdInputHandler(queue=_global.IP_JSON_QUEUE,
                               ms_manager=PS.MSM)
    PS.StdIH.setDaemon(True)

    # 进度报告线程启动
    PS.PR.start()

    # 标准输入流处理线程启动
    PS.StdIH.start()

    # 阻塞等待多任务扫描管理线程结束
    while True:
        try:
            # 判断多任务扫描控制线程是否结束
            if PS.MSM.isAlive():
                _time.sleep(6)
                continue
            # 如果结束,终止其他戏那场
            else:
                _time.sleep(2)
                # 终止进度报告线程
                PS.PR.stop()
                _time.sleep(1)
                # 终止标准输入流处理线程
                PS.StdIH.stop()
                break
            # end if
        # 响应ctrl^c 终止所有线程 退出
        except KeyboardInterrupt:
            PS.logger.print_info('Keyboard Interruption, exit...')
            PS.MSM.stop()
            break
        # end while

    print_end()
    _os.system('stty sane')

if __name__ == '__main__':
    user_check()
    main()
