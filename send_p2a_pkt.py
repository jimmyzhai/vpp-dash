#!/usr/bin/python3
# -*- coding: utf-8 -*-
import re
import sys
from scapy.all import *

class DASH(Packet):
    name = "DASH"
    fields_desc = [ XShortEnumField("type", 0x800, ETHER_TYPES),
                    ByteField("length", 30),
                    ByteEnumField("metadata_type", 1, { 1: "PIPELINE2APP", 2: "APP2PIPELINE" }),
                    #MACField("flow_key_eni", None),
                    ShortField("flow_key_eni", 2),
                    ShortEnumField("flow_key_ip_proto", 6, IP_PROTOS),
                    IPField("flow_key_src_ip", "1.1.1.1"),
                    IPField("flow_key_dst_ip", "2.2.2.2"),
                    XShortField("flow_key_src_port", 0x5566),
                    XShortField("flow_key_dst_port", 0x6677),
                    IntField("flow_data_version", 0),
                    ShortEnumField("flow_data_direction", 1, { 1: "OUTBOUND", 2: "INBOUND" }),
                    IntField("flow_data_actions", 0),
                  ]

pkt = Ether(dst="02:fe:23:f0:e4:13",src="00:01:01:01:01:01",type=0x876D)/DASH()/IP(src = "10.1.0.10", dst="10.1.1.1")/TCP(sport=4096, dport=4096)/("a"*64)
sendp(pkt, iface="veth4")

