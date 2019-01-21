# -*- coding:utf-8 -*-

"""
    ID: hd_process.py
    Date: 2017/07/24
    Subject: 端口扫描进程类，继承ScanProcess类
"""
import sys as _sys
import time as _time
import copy as _copy

from libnmap.parser import NmapParser,NmapParserException

import global_variable as _global
from cyberlib_error import *
from cyberlib_my_print import *
from cyberlib_log_stdout import StdOutLog
from scan_process import ScanProcess

__LOG_LEVEL__ = _global.GLOBAL_LOG_LEVEL['scan_process_ps']

class PSPrcoess(ScanProcess):
    """

    """
    def __init__(self, targets):
        super(PSPrcoess,self).__init__(targets)
        self.logger = StdOutLog(__LOG_LEVEL__)

        self.ip_json = {'ip': '', 'mac_info': {'mac': '', 'vendor': '', 'brand': '', 'similarity': ''},
                        'port_list': []}
        self.ip_json_list = []

        if '-O' in _global.OPTIONS:
            self.ip_json.setdefault('os', '')
            self.ip_json.setdefault('nmap_device_type', '')

        # add port_list field if service detect is enabled

        self._port_json = {'port': '', 'type': '',
                           'service': {}}
        self._service_json = {'type': '', 'product': '', 'version': ''}

        self._set_targets(targets)

    def _set_targets(self, targets):
        """设置端口扫描类的成员变量 targets

        :param targets: parameters from the constructor of PSScanProcess class
        :type targets: string or list

        :return: None
        """
        # if the targets is an instance of string
        if isinstance(targets, str):
            self.targets = targets
        # if the targets is an instance of list
        elif isinstance(targets, list):
            # if the elements of the list are instances of dict
            # targets could be ip_json list
            # append ip address in self.targets
            # record the index of ip_json in the ip_json_list
            if isinstance(targets[0], dict):
                self.targets = list()
                self.ip2index = dict()
                self.ip_json_list = targets
                for tar in targets:
                    ip = tar['ip']
                    self.targets.append(ip)
                    self.ip2index[ip] = self.ip_json_list.index(tar)

            # if not ,targets could be just ip list
            else:
                self.targets = targets
            # end if
        else:
            self.targets = None
        # end if

    def print_scan(self):
        """打印nmap扫描结果

        :return: number of inactive ip
        :rtype: int
        """
        try:
            parsed = NmapParser.parse(self.nmproc.stdout)
            self._print_scan(parsed)
            return 0

        except NmapParserException as e:

            print_error(RESULT_PARSE_ERROR, '{0}'.format(e.msg))

            # 解析错误 返回出错的ip数
            hosts_err = len(self.targets)
            self.logger.print_debug("[PSProcess]parse error,{0} ips are error ".format(hosts_err))
            # 尽管错误，还是将json信息输出
            for ip in self.targets:
                self._print_json(ip)
            return hosts_err

    def _print_scan(self, nmap_report):
        """打印解析结果
        :param nmap_report: the data parsed from nmap scan report
        :type nmap_report: NmapObject(NmapHost, NmapService or NmapReport)

        :return: sum of hosts
        """
        title = "Starting Nmap {0}(http://nmap.org)at {1}".format(nmap_report.version,
                                                                  _time.strftime('%H:%M:%S', _time.localtime(float(nmap_report.started))))

        self.logger.print_debug(title)
        for host in nmap_report.hosts:
            port_list = []
            if host.is_up():
                self.logger.print_debug('report for {0}'.format(host.address))
                # fetch service information from nmap report
                port_list = self._fetch_service_info(host)

                # 若os探测开启，则从解析报告中提取os和device type 信息
                if 'os' in self.ip_json:
                    os_info = ''
                    device_type = ''
                    os_info, device_type = self._fetch_os_info(host)

                    self._print_json(host.address, port_list,os_info,device_type)
                else:
                    self._print_json(host.address, port_list)

            else:
                not_found_info = '{0} is not found'.format(host.address)
                self.logger.print_debug(not_found_info)
                self._print_json(host.address, port_list)

        self.logger.print_debug(nmap_report.summary)

        # return total number of scaned ip
        return nmap_report.hosts_total

    def _fetch_service_info(self, nmap_host):
        """从nmap生成的报告中提取端口信息及服务信息

        :param nmap_host: NmapHost object generated from NmapReport
        :type nmap_host: NmapHost

        :return: list of port_info
        :rtype: list
        """
        tmp_port_list = list()
        tmp_port_json = dict()
        tmp_service_json = dict()

        for serv in nmap_host.services:
            state = serv.state

            # copy key and initial value from member variable of class:_port_json
            tmp_port_json = _copy.deepcopy(self._port_json)
            tmp_service_json = _copy.deepcopy(self._service_json)
            tmp_port_json['service'] = tmp_service_json

            # self.logger.print_debug('[after copy ]', tmp_port_json,)
            port = serv.port
            trans_type = serv.protocol
            service_type = serv.service
            self.logger.print_debug("[PSScanProcess]port: {0}, state: {1}, service:{2}".format(port, state, service_type))

            if state in ['open']:
                tmp_port_json['port'] = str(port)
                tmp_port_json['type'] = trans_type
                tmp_port_json['service']['type'] = service_type
            else:
                continue
            # banner is a string includes 'product' field and 'version' field
            banner = serv.banner
            # if banner exists
            if banner:
                banner_dict = self._banner2dict(banner)
                # sometimes there is not 'product' field in the dict
                if 'product' in banner_dict:
                    tmp_port_json['service']['product'] = banner_dict['product']
                # sometimes there is not 'version' field in the dict
                if 'version' in banner_dict:
                    tmp_port_json['service']['version'] = banner_dict['version']

            # append this port_json to the port_list
            # self.logger.print_debug('[before append]', tmp_port_json)
            tmp_port_list.append(tmp_port_json)
            # reset port json
            tmp_port_json = {}
            tmp_servic_json = {}
        return tmp_port_list

    def _banner2dict(self, banner_str):
        """将banner字符串处理为字典类型

        :param banner_str: string of service's banner
        :type banner_str: string

        :retrun: dict of service's banner
        :rtype: dict
        """
        field_list = banner_str.split(' ')
        key_index = []
        banner_dict = {}
        if 'product:' in field_list:
            indexofp = field_list.index('product:')
            banner_dict['product'] = indexofp
        if 'version:' in field_list:
            indexofv = field_list.index('version:')
            banner_dict['version'] = indexofv

        for field in field_list:
            if ':' in field:
                key_index.append(field_list.index(field))
        for key in banner_dict:
            kindex = banner_dict[key]
            # if the index of key(version and product) is not the last element of the key_index
            if key_index.index(kindex) < len(key_index)-1:
                next_index = key_index[key_index.index(kindex)+1]
                banner_dict[key] = ' '.join(field_list[kindex+1:next_index])
            # if the index is the last one of the key_index
            # it also means the key(version or product) is the last key in the field_list
            # the element that remains in the field_list is the value of thar key
            else:
                banner_dict[key] = ' '.join(field_list[kindex+1:])

        self.logger.print_debug("banner_dict: {0}".format(banner_dict))

        return banner_dict

    def _fetch_os_info(self, nmap_host):
        """从nmap生成的报告中提取os信息和设备类型信息

        :param nmap_host: NmapHost object generated from NmapReport
        :type nmap_host: NmapHost

        :return: os info and device type
        :rtype: tuple (os_info,nmap_device_type) or ('','')
        """
        dtype_statistic = {}
        os_statistic = {}

        for os in nmap_host.os_class_probabilities():
            # 统计每个类型各自出现的次数
            if os.type not in dtype_statistic:
                dtype_statistic.setdefault(os.type, 1)
            else:
                dtype_statistic[os.type] += 1
            if os.osfamily not in os_statistic:
                os_statistic.setdefault(os.osfamily, 1)
            else:
                os_statistic[os.osfamily] += 1

        if dtype_statistic:
            dtype = sorted(dtype_statistic.iteritems(), key=lambda dtype_statistic: dtype_statistic[1])
            # 打印出现次数最多的类型
            nmap_device_type, prob1 = dtype[-1]
            self.logger.print_debug("nmap_device_type: {0}({1})\t".format(nmap_device_type, prob1))
        else:
            nmap_device_type = ''

        if os_statistic:
            os_list = sorted(os_statistic.iteritems(), key=lambda os_statistic: os_statistic[1])
            self.logger.print_debug("os_list:{0}".format(os_list))
            os_info, prob2 = os_list[-1]
            self.logger.print_debug("os: {0}({1})".format(os_info, prob2))
        else:
            os_info = ''
        return os_info, nmap_device_type

    def _print_json(self, ip='', port_json=[], os_info="", device_type=""):
        if not ip:
            return
        # copy key and initial value from member variable of class:ip_json
        tmp_ip_json = self.ip_json
        # for key in self.ip_json:
        #     tmp_ip_json.setdefault(key,self.ip_json[key])
        # get the old version json of specified ip
        if self.ip_json_list:
            old_ip_json = self.ip_json_list[self.ip2index[ip]]
            # update the value according to old version
            for key in old_ip_json:
                tmp_ip_json[key] = old_ip_json[key]

        if port_json:
            tmp_ip_json['port_list'] = port_json
        else:

            allport_close_report = 'all ports are closed on  {0}'.format(ip)
            self.logger.print_debug(allport_close_report)

        if os_info:
            tmp_ip_json['os'] = os_info
        if device_type:
            tmp_ip_json['nmap_device_type'] = device_type

        # @output{'IP_info':{'ip':'192.168.0.1','mac':'00:00:00:ec:12:32','vendor':'tp-link',
        #                    'os':'Windows','nmap_device_type':'general purpose',
        #                    'port_list':[{'port':'80','type':'tcp','service':{"type":"http",'product': "Apache httpd",'version':'4.3.0'}}]}}
        print_ip(tmp_ip_json)