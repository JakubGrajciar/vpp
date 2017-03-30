#!/usr/bin/env python

import socket
import unittest
import struct
import inspect

from framework import VppTestCase, VppTestRunner
from extra_vpp import ExtraVpp, RemoteClass
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.inet import IPerror, TCPerror, UDPerror, ICMPerror
from scapy.layers.l2 import Ether, ARP
from scapy.data import IP_PROTOS
from util import ppp


class TestMemifVpp2(ExtraVpp):
    """ Second instance of VPP for memif tests """

    @classmethod
    def setUpClass(cls):
        super(TestMemifVpp2, cls).setUpClass()

        try:
            cls.create_pg_interfaces([0])
            cls.create_loopback_interfaces([0])
            cls.loopback0 = cls.lo_interfaces[0]
            cls.loopback0.config_ip4()
            cls.loopback0.admin_up()
            cls.pg0.config_ip4()
            cls.pg0.configure_ipv4_neighbors()
            cls.pg0.admin_up()
            cls.pg0.resolve_arp()

        except Exception:
            super(TestMemifVpp2, cls).tearDownClass()
            raise

    def tearDown(self):
        super(TestMemifVpp2, self).tearDown()
        if not self.vpp_dead:
            self.logger.info(self.vapi.cli("show interfaces address"))
            self.logger.info(self.vapi.cli("show memif"))


class MemifApi(object):

    @staticmethod
    def create_memif(vpp, key=0, role='slave', socket='',
            ring_size=0, buffer_size=0, hw_addr='00:00:00:00:00:00'):
        """
        Create Memif interface

        :param vpp: VPPTestCase instance
        :param key: 64bit integer used to authenticate and match opposite sides
                    of the connection
        :param role: role of the interface in the connection (master/slave)
        :param socket: filename of the socket to be used for connection
                       establishment
        :returns: sw_if_index
        """
        role_id = (1 if role == 'slave' else 0)
        reply = vpp.vapi.memif_create(
                    role_id,
                    key,
                    socket,
                    ring_size,
                    buffer_size,
                    hw_addr)
        return reply.sw_if_index

    @staticmethod
    def delete_memif(vpp, sw_if_index):
        """
        Delete Memif interface

        :param vpp: VPPTestCase instance
        :param sw_if_index: software index of the interface to delete
        """
        vpp.vapi.memif_delete(sw_if_index)

    @staticmethod
    def dump_memif(vpp, sw_if_index=None):
        """
        Dump a specific Memif interface or all of them

        :param vpp: VPPTestCase instance
        """
        memifs = vpp.vapi.memif_dump()
        if sw_if_index is None:
            return memifs
        else:
            for memif in memifs:
                if memif.sw_if_index == sw_if_index:
                    return memif
        return None

    @staticmethod
    def log_memif_config(vpp):
        """
        Log details of all memory interfaces

        :param vpp: VPPTestCase instance
        """
        dump = vpp.vapi.memif_dump()
        for memif in dump:
            if_name = memif.if_name.rstrip('\0')
            vpp.logger.info('%s: sw_if_index %d mac %s',
                    if_name, memif.sw_if_index,
                    ':'.join([('%0.2x' % ord(i)) for i in memif.hw_addr]))
            vpp.logger.info('%s: key %d socket %s role %s',
                    if_name, memif.key, memif.socket_filename.rstrip('\0'),
                    'slave' if memif.role else 'master')
            vpp.logger.info('%s: ring_size %d buffer_size %d',
                    if_name, memif.ring_size, memif.buffer_size)
            vpp.logger.info('%s: state %s link %s',
                    if_name,
                    'up' if memif.admin_up_down else 'down',
                    'up' if memif.link_up_down else 'down')



class TestMemif(VppTestCase):
    """ Memif Test Cases """

    @classmethod
    def setUpClass(cls):
        cls.vpp2 = RemoteClass(TestMemifVpp2)
        cls.vpp2.start_remote()

        super(TestMemif, cls).setUpClass()
        cls.vpp2.setUpClass()

        try:
            cls.create_pg_interfaces([0])
            cls.create_loopback_interfaces([0])
            cls.loopback0 = cls.lo_interfaces[0]
            cls.loopback0.config_ip4()
            cls.loopback0.admin_up()
            cls.pg0.config_ip4()
            cls.pg0.configure_ipv4_neighbors()
            cls.pg0.admin_up()
            cls.pg0.resolve_arp()
            cls.icmp_id = 6305

        except Exception:
            super(TestMemif, cls).tearDownClass()
            raise

    def setUp(self):
        super(TestMemif, self).setUp()
        self.vpp2.setTestFunctionInfo(self._testMethodName,
                self._testMethodDoc)
        self.vpp2.setUp()

    def create_icmp(self, in_if, out_if, ttl=64):
        """
        Create ICMP packet

        :param in_if: Inside interface
        :param out_if: Outside interface
        :param ttl: TTL of the generated packet
        """
        p = (Ether(dst=in_if.local_mac, src=in_if.remote_mac) /
             IP(src=in_if.remote_ip4, dst=out_if.remote_ip4, ttl=ttl) /
             ICMP(id=self.icmp_id, type='echo-request'))
        return p

    def clear_memif_config(self):
        """ Clear Memif configuration """
        # VPP 1
        for memif in MemifApi.memif_dump(self):
            self.logger.info("Deleting memif sw_if_index: %d" % memif.sw_if_index)
            MemifApi.memif_delete(self, memif.sw_if_index)
        MemifApi.log_memif(self)
        # VPP 2
        for memif in MemifApi.memif_dump(self.vpp2):
            self.vpp2.logger.info("Deleting memif sw_if_index: %d" % memif.sw_if_index)
            MemifApi.memif_delete(self.vpp2, memif.sw_if_index)
        MemifApi.log_memif(self.vpp2)

    def test_memif_connect(self):
        """ Memif connect test """

        # VPP 1
        master_if_index = MemifApi.create_memif(self, 15, 'master',
                '/tmp/vpp.sock', 512, 4096, 'aa:bb:cc:11:22:33')
        self.logger.info("Created memif sw_if_index: %d" % master_if_index)

        self.vapi.sw_interface_add_del_address(
            master_if_index, socket.inet_pton(socket.AF_INET, '192.168.2.1'), 24)
        self.vapi.sw_interface_set_flags(master_if_index, admin_up_down=1)

        # VPP 2
        slave_if_index = MemifApi.create_memif(self.vpp2, 15, 'slave',
                '/tmp/vpp.sock', 512, 4096)
        self.vpp2.logger.info("Created memif sw_if_index: %d" % slave_if_index)

        self.vpp2.vapi.sw_interface_add_del_address(
            slave_if_index, socket.inet_pton(socket.AF_INET, '192.168.2.2'), 24)
        self.vpp2.vapi.sw_interface_set_flags(slave_if_index, admin_up_down=1)

        # Wait
        self.sleep(4, "waiting for memif connection to establish")
        MemifApi.log_memif_config(self)
        MemifApi.log_memif_config(self.vpp2)

        # Test VPP 1
        master = MemifApi.dump_memif(self, master_if_index)
        self.assertIsNotNone(master)
        self.assertEqual(master.link_up_down, 1)

        # Test VPP 2
        slave = MemifApi.dump_memif(self.vpp2, slave_if_index)
        self.assertIsNotNone(slave)
        self.assertEqual(slave.link_up_down, 1)

        # TODO: test with traffic
        #icmp = self.create_icmp(self.pg0, self.pg1)
        #self.pg0.add_stream([icmp])
        #self.pg_enable_capture(self.pg_interfaces)
        #self.pg_start()
        #capture = self.pg1.get_capture(len(pkts))
        #self.verify_capture(capture)

    def tearDown(self):
        super(TestMemif, self).tearDown()
        if not self.vpp_dead:
            self.logger.info(self.vapi.cli("show interfaces address"))
            self.logger.info(self.vapi.cli("show memif"))
        self.vpp2.tearDown()
        if not self.vpp_dead and not self.vpp2.vpp_dead:
            self.clear_memif_config()

    @classmethod
    def tearDownClass(cls):
        cls.vpp2.tearDownClass()
        cls.vpp2.quit_remote()
        cls.vpp2.join()
        super(TestMemif, cls).tearDownClass()

if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
