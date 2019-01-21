# -*- coding:utf-8 -*-

"""
    ID: config_parser1.py
    Date: 2016/08/09
    Subject:命令行参数解析模块

"""

import sys as _sys
import re as _re
import os as _os
from IPy import IP
import global_variable as _global
# from global_variable import CONFIG_DIR
from cyberlib_my_print  import *
from cyberlib_error import ARG_ERROR
from cyberlib_cmd_parser import CMDConfig
from cyberlib_log_stdout import StdOutLog

from port_handler import PortHandler
from ip_parser import IPParser
from error import BLACKLIST_ERROR

__LOG_LEVEL__ = _global.GLOBAL_LOG_LEVEL['cmd_parser']

# 匹配ip和ip_cidr
IP_RE = _re.compile(r"(?<!\d\.)(?<!\d)(?:\d{1,3}\.){3}\d{1,3}(?!\d|(?:\.\d))")
IP_CIDR_RE = _re.compile(r"(?<!\d\.)(?<!\d)(?:\d{1,3}\.){3}\d{1,3}/\d{1,2}(?!\d|(?:\.\d))")

class CMDParser:

    def __init__(self, *argv, **args):
        """CMDParser类的构造函数
        """
        self.logger = StdOutLog(__LOG_LEVEL__)

        config_file_name = _global.CONFIG_DIR+'/cmd_arg.ini'
        self.cmd_options = {}
        self.parser = CMDConfig(config_file_name).get_parser()
        self.ip = IPParser()

        self._parse_is_valid = False

        self._from_file = False

        self.scan_options_list = []
        self.scan_options_dict = {}
        self.targets = []

    def parse(self, cmd=None):
        """解析命令行参数

        :param cmd: command to launch scan process
        :type cmd: string or None
        """
        if cmd is None:
            args = self.parser.parse_args()
        else:
            args = self.parser.parse_args(cmd.split(' '))

        # for key in args.__dict__:
            # self.cmd_options[key] = args.__dict__[key]
        # self.cmd_options ={opt:args.__dict__[opt] for opt in args.__dict__}
        self.cmd_options.update(args.__dict__)

        self._parse_is_valid = True
        self.logger.print_debug("[CMDParser]args:{0}".format(args.__dict__))
        self.logger.print_debug("[CMDParser]cmd_options", self.cmd_options)

    def _args_check(self):
        """命令行参数合法性检测

        """
        if 'target_parse' not in self.cmd_options and 'ip_file_parse' not in self.cmd_options:
            print_error(ARG_ERROR, 'argument --target/-t is required')
            exit(0)

        if self.cmd_options['intensity_parse'] == 0 and 'ports_parse' in self.cmd_options:
            # raise ParseError('--addition-port is required when --intensity is 0')
            print_error(ARG_ERROR, 'argument --addition-port is required when --intensity is 0')
            exit(0)

        # check if the addition port number or addition port range is legal
        if 'ports_parse' in self.cmd_options:
            for ports in self.cmd_options['ports_parse'][0]:
                if '-' in ports:
                    pl = ports.split('-')
                    if len(pl) != 2:
                        print_error(ARG_ERROR, 'invalid port range:{0}'.format(ports))
                        exit(2)
                    left, right = pl[0], pl[1]
                    try:
                        int(left)
                        int(right)
                    except ValueError:
                        print_error(ARG_ERROR, 'invalid port range:{0}'.format(pl))
                        exit(2)

        if 'blacklist_filepath_parse' in self.cmd_options:
            filepath = self.cmd_options['blacklist_filepath_parse']
            if len(filepath) > 0 and _os.path.exists(filepath) is not True:
                print_error(ARG_ERROR,'--blacklist file does not exist: {0}'.format(filepath))
                exit(0)

            # check blacklist file,
            # if there is wrong formed line in blacklist file,  exit
            with open(filepath, 'r') as f:
                line_no = 1
                while True:
                    try:
                        ip_address= f.next()[:-1]
                        line_no += 1
                        # skip comment
                        if ip_address:
                            if '#' in ip_address.split():
                                continue
                            if not self.ip.is_valid_ip(ip_address):
                                print_error(BLACKLIST_ERROR, "'{0}' at line {1}".format(ip_address,line_no))
                                f.close()
                                exit(0)
                    except StopIteration:
                        break

        if 'ip_file_parse' in self.cmd_options:
            filepath = self.cmd_options['ip_file_parse']
            if len(filepath) > 0 and _os.path.exists(filepath) is not True:
                print_error(ARG_ERROR,'--ip file does not exist: {0}'.format(filepath))
                exit(0)

    def _set_port(self):
        """根据命令行中指定端口的相关参数--protocol 和--intensity
        确定主机发现要使用的端口集合

        :return: string of port arguments
        :rtype: string
        """
        port_proto = {'tcp': [False, 0],
                      'udp': [False, 0],
                      'promis': [False, 0]}
        ports_intensity = [0, 15, 50, 100, 500, 100]

        proto = self.cmd_options['proto_parse']
        intensity = self.cmd_options['intensity_parse']


        if 'ports_parse' in self.cmd_options:
            ports = self.get_addition_port(self.cmd_options['ports_parse'][0])
        else:
            ports = []

        # get --addition-port-tcp if it presents in the command line
        tcp_ports = [] if 'ports_tcp_parse' not in self.cmd_options \
            else self.cmd_options['ports_tcp_parse'][0]
        # get --addition-port-udp if it presents in the command line
        udp_prots = [] if 'ports_udp_parse' not in self.cmd_options \
            else self.cmd_options['ports_udp_parse'][0]

        port_args = {'tcp': ' -PS', 'udp': ' -PU', 'sctp': ' -PY'}
        ports_argv = ''

        port_proto[proto][0] = True
        port_proto[proto][1] = ports_intensity[intensity]

        ph = PortHandler(top=ports_intensity[intensity], proto=proto)
        pl = ph.get_list()

        #
        # load ports from sorted-port file according to intensity which is from command
        #
        for info in pl:
            port, proto1 = info.split('/')
            if port is not None:
                port_args[proto1] = port_args[proto1]+port+','

        #
        # add additional ports to portlist
        #
        if proto == 'promis':
            for item in ports:
                if str(item) not in port_args['tcp']:
                    port_args['tcp'] = port_args['tcp'] + str(item) + ','
                if str(item) not in port_args['udp']:
                    port_args['udp'] = port_args['udp'] + str(item) + ','
        else:
            for item in ports:
                # if the addition port in the port list, remove the addition port
                if str(item) in port_args[proto]:
                    continue
                port_args[proto] = port_args[proto] + str(item) + ','

        for item in tcp_ports:
            if str(item)+'/tcp' in pl:
                continue
            port_args['tcp'] = port_args['tcp'] + str(item) + ','
        for item in udp_prots:
            if str(item)+'/udp' in pl:
                continue
            port_args['udp'] = port_args['udp'] + str(item) + ','

        for proto in port_args:
            if len(port_args[proto]) > 4:
                ports_argv += ''.join(port_args[proto][:-1])
        # self.ports_argv = ports_argv

        return ports_argv

    def init_args(self, type_dict=False):
        """将解析后的命令行参数初始化
           初始化后的参数及参数值保存至字典和列表中，并根据参数确定要返回的类型

        :param type_dict: return dict of scan options if True,default False
        :type type_dict: boolean

        :return: scan options from parsed
        :rtype: list or dict
        """

        if not self._parse_is_valid:
            print 'cmd options are not parsed'
            return {} if type_dict else []

        self._args_check()
        # add port
        ports_str = self._set_port()
        self.scan_options_list.append(ports_str)
        self.scan_options_dict[' '] = ports_str

        # add blacklist
        if 'blacklist_filepath_parse' in self.cmd_options:
            filepath = self.cmd_options['blacklist_filepath_parse']
            if filepath:
                self.scan_options_list.append(' --excludefile=' + filepath)
                self.scan_options_dict[' --excludefile'] = filepath

        # add topo-probe
        if self.cmd_options['topo_probe_parse'] is True:
            self.scan_options_list.append(' --traceroute')
            self.scan_options_dict['  '] = '--traceroute'

        # add ipfile
        if 'ip_file_parse' in self.cmd_options:
            filepath = self.cmd_options['ip_file_parse']
            if filepath:
                self._from_file = True

        self.logger.print_debug('[CMDParser]options:{0}\n{1}'.format(self.scan_options_list, self.scan_options_dict))

        return self.scan_options_list if not type_dict \
            else self.scan_options_dict

    def decomepose_ip(self):
        """将命令行参数中指定的ip地址范围分解为单个ip地址

        :return: list of ip targets
        :rtype: list
        """
        if not self._parse_is_valid:
            print 'cmd options are not parsed'
            return []
        if self._from_file:
            target_spec = self._read_ip_file()
        else:
            target_spec = self.cmd_options['target_parse'][0]
        # self.logger.print_debug('[CMDParser]target_spec:',target_spec)
        # ip_target = IPHandler(target_spec).get_nmap_ip_parameter()
        ip_target = self.ip.get_nmap_ip_parameter(target_spec)
        self.targets = list(ip_target)
        # use set() to remove duplicate ip address
        # self.targets = list(set(ip_target))
        self.logger.print_debug('[CMDParser]ip targets:', len(self.targets))
        # 删除黑名单中的Ip地址
        black_ip_list = self._read_blacklist_file()
        if black_ip_list:
            for ip in black_ip_list:
                if ip in self.targets:
                    self.targets.remove(ip)
        return self.targets

    def _read_ip_file(self):
        """从命令行参数指定的文件中读取ip地址

        :return: list of ip addresses
        :rtype: list
        """
        filepath = self.cmd_options['ip_file_parse']
        ip_list = []
        with open(filepath, 'r') as f:
            for line in f:
                # 去除换行符
                line = line.strip('\n')
                if line in IP_RE.findall(line):
                    ip_list.append(line)
                elif line in IP_CIDR_RE.findall(line):
                    cidr = IP(line, make_net=True)
                    for ip in cidr:
                        ip = str(ip)
                        ip_list.append(ip)
        f.close()
        return ip_list

    def _read_blacklist_file(self):

        # 获取黑名单ip
        black_ip_list = []
        if 'blacklist_filepath_parse' in self.cmd_options:
            if self.cmd_options['blacklist_filepath_parse']:
                filepath = self.cmd_options['blacklist_filepath_parse']
                with open(filepath, 'r') as f:
                    for line in f:
                        # 去除换行符
                        line = line.strip('\n')
                        if line in IP_RE.findall(line):
                            black_ip_list.append(line)
                        elif line in IP_CIDR_RE.findall(line):
                            cidr = IP(line, make_net=True)
                            for ip in cidr:
                                ip = str(ip)
                                black_ip_list.append(ip)
                f.close()
        return black_ip_list


    def get_addition_port(self, addition_port):
        """
        通过此方法将命令行参数的额外端口格式拼接成nmap能够识别的格式
        :param addition_port: 命令行参数传递过来的额外端口类型：['120', '1-100']
        :return: ports: [1,2,3,4,...,100]
        """
        ports = []
        for port in addition_port:
            if '-' in port:
                pl = port.split('-')
                left, right = pl[0], pl[1]
                for i in range(int(left), int(right)+1):
                    ports.append(i)
            else:
                ports.append(int(port))
        # 去掉重复
        ports = list(set(ports))
        return ports






