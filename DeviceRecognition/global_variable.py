#!/usr/bin/env python
#-*- coding:utf-8 -*-
### 全局变量存放位置 ###
import os as _os

# 程序主路径
Project_Main = _os.path.dirname(_os.path.realpath(__file__))
# 程序父路径
FATHER_DIR = '/'.join(Project_Main.split('/')[:-1])

# 配置文件路径
CONFIG_DIR = _os.path.join(Project_Main,'config')

from cyberlib_ip_json_queue import IPJsonQueue

# 需要执行弱密钥检测的ip_json队列
IP_JSON_QUEUE = IPJsonQueue()

# 各个子模块的调试模式
GLOBAL_LOG_LEVEL = {'dr_main': 3,
                    'progress_reporter': 3}


