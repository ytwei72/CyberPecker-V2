# -*- coding:utf-8 -*-
"""

   ID: port_handler.py
   Date: 2016/04/17
   Time: 12:04:06
   Subject: 处理端口参数，返回指定的端口列表，默认1000个热门 tcp端口
"""
import os as _os
import sys as _sys

from global_variable import CONFIG_DIR


class PortHandler:
    def __init__(self,top=1000,proto='tcp'):
        """
        proto=['tcp','udp','promis']
        """
        self.count =top
        self.proto =proto
        self.port_list=[]
        self.__set_port()

    def __set_port(self):
        """
        get port from file: sorted-port sorted-udp sorted-tcp
        """
        file_name =""
        if self.proto =='tcp':
            file_name ='sorted-tcp'
        elif self.proto =='udp':
            file_name = 'sorted-udp'
        elif self.proto =='sctp':
            file_name ='sorted-sctp'
        else:
            pass
        n = 0
        # port_file = file_name
        port_file = CONFIG_DIR+'/'+file_name
        with open(port_file,'r') as f:
            for line in f:
                if n >= self.count:
                    break
                self.port_list.append(line.split('\t')[1])
                n+=1
        f.close()

    def get_list(self):
        """
        port_list ['80/tcp','443/tcp',...]
        """
        return self.port_list