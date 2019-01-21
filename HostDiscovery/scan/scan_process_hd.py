# -*- coding:utf-8 -*-

"""
    ID: scan_process_hd.py
    Date: 2017/07/21
    Subject: 主机发现进程类，继承ScanProcess类
"""
import sys as _sys
import time as _time

from libnmap.parser import NmapParser,NmapParserException

import global_variable as _global
from cyberlib_my_print import *
from cyberlib_get_brand import get_brand
from cyberlib_log_stdout import StdOutLog
from cyberlib_error import *

from scan_process import ScanProcess

__LOG_LEVEL__ = _global.GLOBAL_LOG_LEVEL['scan_process_hd']


class HDProcess(ScanProcess):
    """

    """
    def __init__(self, targets):
        super(HDProcess, self).__init__(targets)

    def print_scan(self):
        """打印nmap扫描结果

        :return: number of inactive ip
        :rtype: int
        """
        try:
            parsed = NmapParser.parse(self.nmproc.stdout)
            hosts_down = self._print_scan(parsed)
            return hosts_down

        except NmapParserException as e:
            self.logger.print_info("[HDProcess]Exception raised while parsing scan:{0}".format(e.msg))
            print_error(RESULT_PARSE_ERROR,'{0}'.format(e.msg))

            # 解析错误 所有ip均视为不存活，返回总数
            hosts_down = len(self.targets)
            self.logger.print_info("[HDProcess]parse error,{0} ip are regarded as down".format(hosts_down))
            return hosts_down

    def _print_scan(self, nmap_report):
        """打印解析结果
        :param nmap_report: the data parsed from nmap scan report
        :type nmap_report: NmapObject(NmapHost, NmapService or NmapReport)

        :return: number of inactive ip
        :rtype: int
        """
        self.logger.print_info("Starting Nmap {0}(http://nmap.org)at {1}".format(nmap_report.version,
                                                                           _time.strftime('%H:%M:%S', _time.localtime(float( nmap_report.started)))))

        for host in nmap_report.hosts:
            if host.is_up():
                self.logger.print_info('report for {0}'.format(host.address))
                # log_debug('report for {0}'.format(host.address))
                self._print_json(host.address,
                                 host.mac,
                                 host.vendor)
                # self.logger.print_info('distance from {0}：{1}'.format(host.address,host.distance))

        self.logger.print_info(nmap_report.summary)

        # return inactive
        if nmap_report.hosts_total == 0:
            print_error(NOROUTE_TO_HOST,'{0}-{1}: {2} hosts (maybe in blacklist)'.format(self.targets[0],self.targets[-1],len(self.targets)))
            self.logger.print_info("[HDProcess]runtime error,{0} ip are regarded as down".format(len(self.targets)))
            return len(self.targets)
        elif nmap_report.hosts_down != -1:
            return nmap_report.hosts_down
        else:
            return nmap_report.hosts_total

    def _print_json(self, ip='', mac='', vendor=''):
        if not ip:
            return
        tmp_ip_json = {'ip': '', 'mac_info': {'mac': '', 'vendor': '', 'brand': '', 'similarity': ''}}

        tmp_ip_json['ip'] = ip
        if mac:
            tmp_ip_json['mac_info']['mac'] = mac
        if vendor:
            tmp_ip_json['mac_info']['vendor'] = vendor
            # compare each brand to vendor, get the brand information
            brand = get_brand(vendor)
            if brand:
                tmp_ip_json['mac_info']['brand'] = brand
                tmp_ip_json['mac_info']['similarity'] = '99'
            brand = ''
        # @output{'IP_info':{'ip':'192.168.0.1','mac':'00:00:00:ec:12:32','vendor':'tp-link'}}
        print_ip(tmp_ip_json)