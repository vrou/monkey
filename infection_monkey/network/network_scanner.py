import itertools
import logging
import time
from functools import partial
from multiprocessing.dummy import Pool as ThreadPool

from config import WormConfiguration
from info import local_ips, get_interfaces_ranges
from common.network.network_range import *
from model import VictimHost
from . import HostScanner

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
        LOG.info("Base local networks to scan are: %r", self._ranges)

    def get_victim_machines(self, scan_type, max_find=5, scan_size=ITERATION_BLOCK_SIZE, stop_callback=None):
        """
        Generator of victim machines based on the network scanning configuration.
        Scans in parallel scan_size number of machines.
        :param scan_type: scanner_class type
        :param max_find:  Maximum number of victims to find
        :param scan_size: Number of hosts to scan in parallel
        :param stop_callback: Callback per iteration to check if we should stop activity
        :return: Generates VictimHost instances
        """

        scanner = scan_type()
        victims_count = 0
        pool = ThreadPool()

        for net_range in self._ranges:
            LOG.debug("Scanning for potential victims in the network %r", net_range)
            for scan_chunk in _grouper(net_range, scan_size):
                # scan_chunk is a iterable of IP addresses
                if stop_callback and stop_callback():
                    LOG.debug("Got stop signal")
                    return

                # skip self IP address
                scan_chunk = [x for x in scan_chunk if x not in self._ip_addresses]
                # skip IPs marked as blocked
                bad_victims = [x for x in scan_chunk if x in WormConfiguration.blocked_ips]
                for victim in bad_victims:
                    LOG.info("Skipping %s due to blacklist" % victim)

                scan_chunk = [x for x in scan_chunk if x not in WormConfiguration.blocked_ips]

                LOG.debug("Scanning %r...", scan_chunk)

                results = pool.map(partial(self.scan_machine, scanner=scanner),
                                   scan_chunk)
                victims_chunk = [x for x in results if x] # filter out dead addresses

                for victim in victims_chunk:
                    victims_count += 1
                    yield victim
                    if victims_count >= max_find:
                        LOG.debug("Found max needed victims (%d), stopping scan", max_find)
                        return

                if SCAN_DELAY:
                    time.sleep(SCAN_DELAY)

    @staticmethod
    def scan_machine(target_ip, scanner):
        """
        Scans specific machine using given scanner
        :param target_ip: VictimHost machine
        :param scanner: HostScanner instance
        :return: Victim or None if victim isn't alive
        """
        LOG.debug("Scanning potential target_ip: %r", target_ip)
        victim = VictimHost(target_ip)
        if scanner.is_host_alive(victim):
            LOG.debug("Found potential target_ip: %r", victim)
            return victim
        else:
            return None
