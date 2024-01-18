#!/bin/bash

[ -d /var/log/vpp ] || mkdir -p /var/log/vpp

sysctl vm.nr_hugepages=512
sysctl vm.max_map_count=1548

exec vpp -c /etc/vpp/startup.conf
