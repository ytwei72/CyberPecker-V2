# -*- coding:utf-8 -*-
"""
    ID: ip_handler.py
    Date: 2016/05/16
    Time: 09:16:38
    Subject: handle IP address in CIDR format by using netaddr
    ==================================Update===========================
    ID: ip_parser.py
    Date: 2016/07/14
    Subject: change the class name,parse an IP parameter,return every IP Address into list
    Author: @CR

"""
from netaddr.core import AddrFormatError
from netaddr.ip import IPAddress,IPNetwork
from netaddr.compat import _iter_range,_is_str,_iter_next

from cyberlib_my_print import *
from cyberlib_error import ARG_ERROR

class IPParser:
    """

    """
    def __init__(self,*nmap_target_spec):
        self.raw_spec = nmap_target_spec
        # print "[IPParser]>>",self.raw_spec
        self.target =[]
        self.is_subnet = False
        self.target_obj =[]
        self.tmp_target =[]

    def get_nmap_ip_parameter(self):
        """
        :return: list of ip set as nmap's target parameter
        :rtype: list
        """
        for target in self.raw_spec:
            ip_list = [str(ip) for ip in self.iter_nmap_range(target)]
            self.target.extend(ip_list)
        return self.target

    def _nmap_octet_target_values(self, spec):
        #   Generates sequence of values for an individual octet as defined in the
        #   nmap Target Specification.
        values = set()

        for element in spec.split(','):
            if '-' in element:
                left, right = element.split('-', 1)
                if not left:
                    left = 0
                if not right:
                    right = 255
                low = int(left)
                high = int(right)
                if not ((0 <= low <= 255) and (0 <= high <= 255)):
                    # raise ValueError('octet value overflow for spec %s!' % spec)
                    print_error(ARG_ERROR, 'octet value overflow for spec %s!' % spec)
                    exit(0)
                if low > high:
                    # raise ValueError('left side of hyphen must be <= right %r' % element)
                    print_error(ARG_ERROR, 'left side of hyphen must be <= right %r' % element)
                    exit(0)
                for octet in _iter_range(low, high + 1):
                    values.add(octet)
            else:
                octet = int(element)
                if not (0 <= octet <= 255):
                    # raise ValueError('octet value overflow for spec %s!' % spec)
                    print_error(ARG_ERROR, 'octet value overflow for spec %s!' % spec)
                    exit(0)
                values.add(octet)

        return sorted(values)

    def _generate_nmap_octet_ranges(self, nmap_target_spec):
        #   Generate 4 lists containing all octets defined by a given nmap Target
        #   specification.
        if not _is_str(nmap_target_spec):
            # raise TypeError('string expected, not %s' % type(nmap_target_spec))
            print_error(ARG_ERROR, '--target string expected, not %s' % type(nmap_target_spec))

        if not nmap_target_spec:
            # raise ValueError('nmap target specification cannot be blank!')
            print_error(ARG_ERROR, 'nmap target specification cannot be blank!')
            exit(0)

        tokens = nmap_target_spec.split('.')

        if len(tokens) != 4:
            # raise AddrFormatError('invalid nmap range: %s' % nmap_target_spec)
            print_error(ARG_ERROR, '--target invalid nmap range: %s' % (nmap_target_spec))
            exit(0)

        return (self._nmap_octet_target_values(tokens[0]),
                self._nmap_octet_target_values(tokens[1]),
                self._nmap_octet_target_values(tokens[2]),
                self._nmap_octet_target_values(tokens[3]))

    def _parse_nmap_target_spec(self, target_spec):
        if '/' in target_spec:
            _, prefix = target_spec.split('/', 1)
            if not (0 < int(prefix) < 33):
                # raise AddrFormatError('CIDR prefix expected, not %s' % prefix)
                print_error(ARG_ERROR, '--target %s CIDR prefix expected, not %s' % (target_spec, prefix))
                exit(0)
            self.is_subnet = True
            try:
                net = IPNetwork(target_spec)
            except (AddrFormatError,):
                print_error(ARG_ERROR, '--target invalid IP address %s' % target_spec)
                exit(0)
            if net.version != 4:
                # raise AddrFormatError('CIDR only support for IPv4!')
                print_error(ARG_ERROR, 'CIDR only support for IPv4!')
                exit(0)

            # yield net
            for ip in net:
                yield ip
        elif ':' in target_spec:
            # nmap only currently supports IPv6 addresses without prefixes.
            yield IPAddress(target_spec)
        else:
            octet_ranges = self._generate_nmap_octet_ranges(target_spec)
            for w in octet_ranges[0]:
                for x in octet_ranges[1]:
                    for y in octet_ranges[2]:
                        for z in octet_ranges[3]:
                            yield IPAddress("%d.%d.%d.%d" % (w, x, y, z), 4)

    def valid_nmap_range(self, target_spec):
        """
        :param target_spec: an nmap-style IP range target specification.

        :return: ``True`` if IP range target spec is valid, ``False`` otherwise.
        """
        try:
            _iter_next(self._parse_nmap_target_spec(target_spec))
            return True
        except (TypeError, ValueError, AddrFormatError):
            pass
        return False

    def iter_nmap_range(self, *nmap_target_spec):
        """
        An generator that yields IPAddress objects from defined by nmap target
        specifications.

        See https://nmap.org/book/man-target-specification.html for details.

        :param *nmap_target_spec: one or more nmap IP range target specification.

        :return: an iterator producing IPAddress objects for each IP in the target spec(s).
        """
        for target_spec in nmap_target_spec:
            if isinstance(target_spec, list):
                for target_spec_item in target_spec:

                    for addr in self._parse_nmap_target_spec(target_spec_item):
                        self.tmp_target.append(addr)
                        yield addr
            else:
                for addr in self._parse_nmap_target_spec(target_spec):
                        yield addr
