# -*- coding:utf-8 -*-
__author__ = 'achelics'

import sys as _sys
import os as _os
from time import ctime,sleep,time, strftime, localtime
# 程序主路径
Project_Main = _os.path.dirname(_os.path.realpath(__file__))
# 程序父路径
FATHER_DIR = '/'.join(Project_Main.split('/')[:-1])
LOGS_DIR = FATHER_DIR + '/logs/OD_logs'
# 配置文件路径
CONFIG_DIR = _os.path.join(Project_Main, 'config')

from cyberlib_ip_json_queue import IPJsonQueue
# 需要执行onivf检测的ip_json队列
IP_JSON_QUEUE = IPJsonQueue()

GL_LOG_LEVEL = {'progress_reporter': 3}

