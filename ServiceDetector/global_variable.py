# -*- coding:utf-8 -*-
"""
    存放全局变量
"""
import os as _os
import sys as _sys

# 程序主路径
MAIN_DIR = _os.path.dirname(_os.path.realpath(__file__))

# 程序父路径
FATHER_DIR = '/'.join(MAIN_DIR.split('/')[:-1])

# 配置文件路径
CONFIG_DIR = _os.path.join(MAIN_DIR,'config')

# 启动扫描进程的参数
OPTIONS = ''

from cyberlib_ip_json_queue import IPJsonQueue

# ip_json 队列
IP_JSON_QUEUE = IPJsonQueue()

# 日志路径
LOG_DIR = '/root/CyberPecker/cyber_logs/sd_logs/'

# 各个子模块的调试模式
GLOBAL_LOG_LEVEL = {'sd_main': 3,
         'cmd_parser': 3,
         'scan_process': 3,
         'scan_process_ps': 3,
         'progress_reporter': 3}