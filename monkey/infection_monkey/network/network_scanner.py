import itertools
import logging
import time
from functools import partial
from multiprocessing.dummy import Pool as ThreadPool

from common.network.network_range import *
from infection_monkey.config import WormConfiguration
from infection_monkey.network.info import local_ips, get_interfaces_ranges
from infection_monkey.model import VictimHost
from infection_monkey.network import TcpScanner, PingScanner

__author__ = 'itamar'

LOG = logging.getLogger(__name__)

SCAN_DELAY = 0
ITERATION_BLOCK_SIZE = 5


def _grouper(iterable, size):
    """
    Goes over an iterable using chunks
    :param iterable: Possible iterable, if required, will cast
    :param size:  Chunk size, last chunk may be smaller
    :return:
    """
    it = iter(iterable)
    while True:
        group = tuple(itertools.islice(it, size))
        if not group:
            break
        yield group


class NetworkScanner(object):
    def __init__(self):
        self._ip_addresses = None
        self._ranges = None
        self.pool = ThreadPool()

    def initialize(self):
        """
        Set up scanning.
        based on configuration: scans local network and/or scans fixed list of IPs/subnets.
        :return:
        """
        # get local ip addresses
        self._ip_addresses = local_ips()

        if not self._ip_addresses:
            raise Exception("Cannot find local IP address for the machine")

        LOG.info("Found local IP addresses of the machine: %r", self._ip_addresses)
        # for fixed range, only scan once.
        self._ranges = [NetworkRange.get_range_obj(address_str=x) for x in WormConfiguration.subnet_scan_list]
        if WormConfiguration.local_network_scan:
            self._ranges += get_interfaces_ranges()
        self._ranges += self._get_inaccessible_subnets_ips()
        LOG.info("Base local networks to scan are: %r", self._ranges)

    def _get_inaccessible_subnets_ips(self):
        """
        For each of the machine's IPs, checks if it's in one of the subnets specified in the
        'inaccessible_subnets' config value. If so, all other subnets in the config value shouldn't be accessible.
        All these subnets are returned.
        :return: A list of subnets that shouldn't be accessible from the machine the monkey is running on.
        """
        subnets_to_scan = []
        if len(WormConfiguration.inaccessible_subnets) > 1:
            for subnet_str in WormConfiguration.inaccessible_subnets:
                if NetworkScanner._is_any_ip_in_subnet([unicode(x) for x in self._ip_addresses], subnet_str):
                    # If machine has IPs from 2 different subnets in the same group, there's no point checking the other
                    # subnet.
                    for other_subnet_str in WormConfiguration.inaccessible_subnets:
                        if other_subnet_str == subnet_str:
                            continue
                        if not NetworkScanner._is_any_ip_in_subnet([unicode(x) for x in self._ip_addresses],
                                                                   other_subnet_str):
                            subnets_to_scan.append(NetworkRange.get_range_obj(other_subnet_str))
                    break

        return subnets_to_scan

    def get_victim_machines(self, max_find=5, scan_size=ITERATION_BLOCK_SIZE, stop_callback=None):
        """
        Finds machines according to the ranges specified in the object
        :param scan_type: A hostscanner class, will be instanced and used to scan for new machines
        :param max_find: Max number of victims to find regardless of ranges
        :param scan_size: Number of hosts to scan in parallel
        :param stop_callback: A callback to check at any point if we should stop scanning
        :return: yields a sequence of VictimHost instances
        """

        tcp_scan = TcpScanner()
        ping_scan = PingScanner()
        victims_count = 0

        for net_range in self._ranges:
            LOG.debug("Scanning for potential victims in the network %r", net_range)
            for scan_chunk in _grouper(net_range, scan_size):

                if stop_callback and stop_callback():
                    LOG.debug("Got stop signal")
                    return

                # skip self IP address
                scan_chunk = [x for x in scan_chunk if x.ip_addr not in self._ip_addresses]

                # skip IPs marked as blocked
                bad_victims = [x for x in scan_chunk if x.ip_addr in WormConfiguration.blocked_ips]
                for victim in bad_victims:
                    LOG.info("Skipping %s due to blacklist" % victim)

                scan_chunk = [x for x in scan_chunk if x.ip_addr not in WormConfiguration.blocked_ips]

                LOG.debug("Scanning %r...", scan_chunk)

                results = self.pool.map(partial(self.scan_machine, scanners=[tcp_scan, ping_scan]),
                                        scan_chunk)
                victims_chunk = [x for x in results if x]  # filter out dead addresses

                for victim in victims_chunk:
                    victims_count += 1
                    yield victim
                    if victims_count >= max_find:
                        LOG.debug("Found max needed victims (%d), stopping scan", max_find)
                        return

                if WormConfiguration.tcp_scan_interval:
                    time.sleep(WormConfiguration.tcp_scan_interval)

    @staticmethod
    def _is_any_ip_in_subnet(ip_addresses, subnet_str):
        for ip_address in ip_addresses:
            if NetworkRange.get_range_obj(subnet_str).is_in_range(ip_address):
                return True
        return False

    @staticmethod
    def scan_machine(target_ip, scanners):
        """
        Scans specific machine using given scanner
        :param target_ip: VictimHost machine
        :param scanners: HostScanner instances
        :return: Victim or None if victim isn't alive
        """
        LOG.debug("Scanning potential target_ip: %r", target_ip)
        victim = VictimHost(target_ip)

        results = [x.is_host_alive(victim) for x in scanners]
        is_alive = any(results)
        if is_alive:
            LOG.debug("Found potential target_ip: %r", victim)
            return victim
        else:
            return None
