# -*- coding:utf-8 -*-

"""
    ID: config_parser1.py
    Date: 2016/08/09
    Subject:命令行参数解析模块
"""

import sys as _sys
import os as _os

import global_variable as _global
# from global_variable import CONFIG_DIR

from cyberlib_my_print import print_error
from cyberlib_cmd_parser import CMDConfig
from cyberlib_error import ARG_ERROR
from cyberlib_log_stdout import StdOutLog

from ip_parser import IPParser
from port_handler import PortHandler

__LOG_LEVEL__ = _global.GLOBAL_LOG_LEVEL['cmd_parser']


class CMDParser:
    """

    """
    def __init__(self, *args, **kwargs):
        """CMDParser类的构造函数
        """
        self.logger = StdOutLog(__LOG_LEVEL__)

        config_file_name = _global.CONFIG_DIR + '/cmd_arg.ini'
        self.cmd_options = {}
        self.parser = CMDConfig(config_file_name).get_parser()

        self._parse_is_valid = False
        self._from_file = False
        self.supported_scan_type = ['sS','sT','sN','sF','sX','sA','sW','sM',  #TCP scan type
                                    'sU',                                     #UDP scan type
                                    'sY','sZ']                                #SCTP scan type

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

    def _arg_check(self):
        """参数合法性检测
        """
        # check if the scan type is supported
        if 'scantype_parse' in self.cmd_options:
            has_tcp_type = False
            supported_scan_type = []
            for stype in self.cmd_options['scantype_parse'][0]:
                if stype not in self.supported_scan_type:
                    print_error(ARG_ERROR, 'unsupported scan type:{0}'.format(stype))
                    exit(2)
                elif stype in self.supported_scan_type[:-3]:
                    if has_tcp_type:
                        print_error(ARG_ERROR,'You specified more than one type of TCP scan: {0}.'.format(stype))
                        exit(0)
                    else:
                        has_tcp_type = True
                    # break
        # check if the addition port number is legal
        if 'portspec_parse' in self.cmd_options:
            for ports in self.cmd_options['portspec_parse']:
                if ':' in ports:
                    flag = ports.split(':')[0]
                    if flag not in ['T', 'U', 'S']:
                        print_error(ARG_ERROR, "invalid port type: '{0}' in '{1}'".format(flag,ports))
                elif '-' in ports:
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
        # check if the port number or port range is legal
        if 'excludeports_parse' in self.cmd_options:
            for ports in self.cmd_options['excludeports_parse'][0]:
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
        # check if the port count is in supported range
        if self.cmd_options['topports_parse'] != 0:
            if 0 < self.cmd_options['topports_parse']:
                pass
            else:
                print_error(ARG_ERROR, 'wrong port count:{0}'.format(self.cmd_options['topports_parse']))
                exit(2)
        # check if the file exists
        if 'ip_file_parse' in self.cmd_options:
            filepath = self.cmd_options['ip_file_parse']
            if len(filepath) > 0 and _os.path.exists(filepath) is not True:
                print_error(ARG_ERROR,'--ip file does not exist: {0}'.format(filepath))
                exit(0)

    def _set_port(self):
        """根据命令行参数中"--scan-type","addition-port","top-ports"
        确定服务探测要使用的端口
        """
        top_number = self.cmd_options["topports_parse"]
        port_proto = {'tcp': ['tcp', ['sS', 'sT', 'sN', 'sF', 'sX', 'sA', 'sW', 'sM']],
                      'udp': ['udp', ['sU']],
                      'sctp': ['sctp', ['sY', 'sZ']]}
        valid_proto = []

        # 获取命令行参数中的扫描类型 若没有指定，则valid_proto 为空
        if "scantype_parse" in self.cmd_options:
            for stype in self.cmd_options["scantype_parse"][0]:
                for proto in port_proto:
                    if stype in port_proto[proto][1]:
                        valid_proto.append(port_proto[proto][0])

        if "portspec_parse" in self.cmd_options:
            adtport_list = self.cmd_options["portspec_parse"]
            adtport_str = ",".join(adtport_list)
            ports_str = {'tcp': [",T:", 0],
                         'udp': [",U:", 0],
                         'sctp': [",S:", 0]}

            if top_number != 0:

                if valid_proto:
                    tmp_proto = valid_proto
                else:
                    tmp_proto = ['tcp']

                for proto in tmp_proto:
                    ph = PortHandler(top=top_number, proto=proto)
                    pl = ph.get_list()
                    #
                    # load ports from sorted-port file according to intensity which is from command
                    #
                    for info in pl:
                        port, proto1 = info.split('/')
                        if port is not None:
                            ports_str[proto][0] = ports_str[proto][0]+port+','
                            ports_str[proto][1] += 1

                for port_proto in ports_str:
                    if ports_str[port_proto][1] != 0:
                        adtport_str += ports_str[port_proto][0][:-1]
            # end if top_number != 0

            # add addition ports
            self.scan_options_list.append(' -p '+adtport_str)
            self.scan_options_dict[' -p '] = adtport_str
        # if self.cmd_options.has_key("portspec_parse"):

        else:
            if top_number != 0:
                self.scan_options_list.append(' --top-ports {0}'.format(self.cmd_options['topports_parse']))
                self.scan_options_dict[' --top-ports'] = ' {0}'.format(self.cmd_options['topports_parse'])

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

        self._arg_check()

        self.scan_options_dict[' '] = ' '
        # add scan type
        if 'scantype_parse' in self.cmd_options:
            self.scan_options_list.append(' -'+' -'.join(self.cmd_options['scantype_parse'][0]))
            self.scan_options_dict[' '] = ' -'+' -'.join(self.cmd_options['scantype_parse'][0])
        # add ports
        self._set_port()
        # add exclude ports
        if 'excludeports_parse' in self.cmd_options:
            self.scan_options_list.append(' --exclude-ports '+' '.join(self.cmd_options['excludeports_parse'][0]))
            self.scan_options_dict[' --exclude-ports '] = ' '.join(self.cmd_options['excludeports_parse'][0])
        # add version detective probe
        if self.cmd_options['version_detec_parse'] is True:
            self.scan_options_list.append(' -sV')
            self.scan_options_dict[' '] += ' -sV'
        # add version detection intensity
        if self.cmd_options['version_intensity_parse'] != 7:
            self.scan_options_list.append(' --version-intensity {0}'.format(self.cmd_options['version_intensity_parse']))
            self.scan_options_dict[' --version-intensity'] = '{0}'.format(self.cmd_options['version_intensity_parse'])
        # add os detective probe
        if self.cmd_options['os_detec_parse'] is True:
            self.scan_options_list.append(' -O')
            self.scan_options_dict[' '] += ' -O'

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
            target_spec = self.cmd_options['target_parse'][0] if 'target_parse' in self.cmd_options else []
        # self.print_debug.debug('[CMDParser]target_spec:',target_spec)
        # ip_target = IPHandler(target_spec).get_nmap_ip_parameter()
        ip_target = IPParser(target_spec).get_nmap_ip_parameter()
        self.targets = list(ip_target)
        # use set() to remove duplicate ip address
        # self.targets = list(set(ip_target))
        self.logger.print_debug('[CMDParser]ip targets:', len(self.targets))

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
                if '#' in line:
                    continue
                else:
                    ip_list.append(line[:-1])
        return ip_list
