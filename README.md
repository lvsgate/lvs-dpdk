# lvs-dpdk

This project has ported LVS FULLNAT/DR/NAT and SNAT-GATEWAY to OpenFastPath(base on odp-dpdk).

NAT are only available on single core while FULLNAT,DR and SNAT-GATEWAY support multi-core.

LVS-FULLNAT origin source code is at https://github.com/alibaba/LVS
LVS-SNAT gateway origin source code is at https://github.com/jlijian3/lvs-snat
OpenFastPath source code is at https://github.com/lvsgate/ofp.git

#Prerequisites
- Intel x86 CPU
- NIC which support flow director
- lvs-dpdk has been compiled and tested on Centos 7.2 with 3.10 kernel

# Build steps
##1. Fetch and compile DPDK
	git clone git://dpdk.org/dpdk ./<dpdk-dir>
	cd <dpdk-dir>
	#git checkout -b 16.07 tags/v16.07 #Maybe this step can be ignored
	make config T=x86_64-native-linuxapp-gcc O=x86_64-native-linuxapp-gcc
	cd <dpdk-dir>/x86_64-native-linuxapp-gcc
	sed -ri 's,(CONFIG_RTE_BUILD_COMBINE_LIBS=).*,\1y,' .config
	sed -ri 's,(CONFIG_RTE_BUILD_SHARED_LIB=).*,\1n,' .config
	sed -ri 's,(CONFIG_RTE_LIBRTE_PMD_PCAP=).*,\1y,' .config
	sed -ri 's,(CONFIG_RTE_LIBRTE_IXGBE_ALLOW_UNSUPPORTED_SFP=).*,\1y,' .config
	cd ..
	make install T=x86_64-native-linuxapp-gcc EXTRA_CFLAGS="-fPIC"
	
	#A env value
	export RTE_SDK=<dpdk-dir>
        export RTE_TARGET=x86_64-native-linuxapp-gcc
	    
##2. Fetch and compile odp-dpdk
	git clone  https://github.com/lvsgate/odp-dpdk.git <odp-dir>
	cd <odp-dir>
	./bootstrap
	./configure --with-platform=linux-dpdk --with-sdk-install-path=<dpdk-dir>/x86_64-native-linuxapp-gcc --prefix=<INSTALL ODP-DPDK TO THIS DIR>
	make
	make install
	
##3. Fetch and compile ofp
	yum install libnl3 libnl3-cli
	git clone https://github.com/lvsgate/ofp.git <ofp-dir>
	cd <ofp-dir>
	./bootstrap
	./configure --with-odp-lib=odp-dpdk --with-odp=<ODP-DPDK INSTALLATION DIR> --enable-shared=no --enable-sp=no
	make

## 4. Fetch and compiled lvs-dpdk tools
	git clone https://github.com/lvsgate/lvs-dpdk.git
	cd lvs-dpdk/tools/keepalived
	./configure
	make
	make install
	cd lvs-dpdk/tools/ipvsadm
	make
	make install

##5. Prepare DPDK for running lvs-dpdk
	echo 1024 > /sys/devices/system/node/node0/hugepages/hugepages-2048kB/nr_hugepages
	mkdir /mnt/huge
	mount -t hugetlbfs nodev /mnt/huge
	modprobe uio
	insmod <dpdk-dir>/x86_64-native-linuxapp-gcc/kmod/igb_uio.ko
	cd <dpdk-dir>
	./tools/dpdk_nic_bind.py --status
	./tools/igb_uio_bind.py --bind=igb_uio <pci-id-1>
	./tools/igb_uio_bind.py --bind=igb_uio <pci-id-2>

		
## 6. Run lvs-dpdk
    cd <ofp-dir>/examples/ofp_vs
    ./ofp_vs -i 0,1 -c 2 -f ofp.conf # -i <port1>,<port2>  
                                     # -c <worker core count> 
                                     # -f <config file include default command which you can change in ofp cli>

## 7. Connect to ofp cli or edit ofp.conf to configure network
    telnet localhost 2345
    type in "?" or "help"
    >>> ?
    # fp0 equal to port number 0 in dpdk
    >>> ifconfig fp0 <ip_addr>/<net_mask> 
    >>> ifconfig fp1 <ip_addr>/<net_mask> 
    #default gw don't work, may be ofp's bug.
    >>> route add 0.0.0.0/0 gw <next hop> dev fp0
    >>> route add <ip_addr>/<net_mask> gw <next hop> dev fp1
    
## 8. Connect to ofp cli or edit ofp.conf to configure fullnat flow director
    telnet localhost 2345
    #In this example, The worker core count is 2.The local address for FULLNAT use net 192.168.210.0/24.
    #Configure your router or swich to route the local address to the interface fp1
    #Add flow director entry for binding local address <a.b.c.d> to rx-queue-id <d%woker_core_count>(d is the last byte of ipv4addr)
    >>> fdir add fp1 proto ipv4 src_ipv4 0.0.0.0 src_port 0 dst_ipv4 192.168.210.100 dst_port 0 queue_id 0
    >>> fdir add fp1 proto ipv4 src_ipv4 0.0.0.0 src_port 0 dst_ipv4 192.168.210.101 dst_port 0 queue_id 1
    >>> fdir add fp1 proto ipv4 src_ipv4 0.0.0.0 src_port 0 dst_ipv4 192.168.210.102 dst_port 0 queue_id 0
    >>> fdir add fp1 proto ipv4 src_ipv4 0.0.0.0 src_port 0 dst_ipv4 192.168.210.103 dst_port 0 queue_id 1
    #You can add these commands above to startup config file ofp.conf
    
    
##9. Connect to ofp
    telnet localhost 2345
    >>> snat enable
    >>> snat add from 10.1.0.0/16 to 0.0.0.0/0 out_dev fp0 source 192.168.50.253 - 192.168.50.253 algo sdh
    >>> snat add from 10.1.0.10/32 to 0.0.0.0/0 out_dev fp0 source 192.168.50.100 - 192.168.50.103 algo sdh
    #The snat source port will be reassign by format port & core_mask = core-index
    #In this example, the worker core count is 2. The formula is port & 0x1 = core-index = rx-queue-id
    #So bind port to queue with this formula.
    >>> fdir add fp0 proto ipv4-tcp src_ipv4 0.0.0.0 src_port 0 dst_ipv4 0.0.0.0 dst_port 0 queue_id 0
    >>> fdir add fp0 proto ipv4-tcp src_ipv4 0.0.0.0 src_port 0 dst_ipv4 0.0.0.0 dst_port 1 queue_id 1
    

## 10. Use ipvsadm and keepalived to configure virtual server on ofp_vs
	#The usage is unchanged.
	#ipvsadm and keepalived will comunicate with ofp_vs process but not the kernel module.
	#Create FULLNAT virtual server
	ipvsadm  -A  -t <vip:vport> -s rr
	ipvsadm  -a  -t <vip:vport> -r <rsip1:rsport> -b
	ipvsadm  -a  -t <vip:vport> -r <rsip2:rsport> -b
	ipvsadm  -P  -t <vip:vport> -z <local_addr1>
	ipvsadm  -P  -t <vip:vport> -z <local_addr2>
	ipvsadm  -P  -t <vip:vport> -z <local_addr3>
	ipvsadm  -P  -t <vip:vport> -z <local_addr4>
	ipvsadm -ln
	ipvadm -G
    
## 11. Try to visit vs now
	curl <vip:vport>

## 12. More details about ofp and odp-dpdk
    http://www.openfastpath.org/
    http://opendataplane.org/
    https://github.com/OpenFastPath/ofp
    https://github.com/lvsgate/ofp
    https://github.com/lvsgate/odp-dpdk

## 13. Support
	email: lvsgateservice@gmail.com
