# lvs-dpdk

This project has ported LVS-FULLNAT to OpenFastPath(base on odp-dpdk).

LVS-FULLNAT origin source code is at https://github.com/alibaba/LVS

OpenFastPath source code is at https://github.com/lvsgate/ofp.git

#Prerequisites
- Intel x86 CPU
- NIC which support flow director
- lvs-dpdk has been compiled and tested on Centos 7.2 with 3.10 kernel

# Build steps
##1. Fetch and compile DPDK
	git clone git://dpdk.org/dpdk ./<dpdk-dir>
	cd <dpdk-dir>
	git checkout -b 16.04 tags/v16.04
	make config T=x86_64-native-linuxapp-gcc O=x86_64-native-linuxapp-gcc
	cd <dpdk-dir>/x86_64-native-linuxapp-gcc
	sed -ri 's,(CONFIG_RTE_BUILD_COMBINE_LIBS=).*,\1y,' .config
	sed -ri 's,(CONFIG_RTE_BUILD_SHARED_LIB=).*,\1n,' .config
	sed -ri 's,(CONFIG_RTE_LIBRTE_PMD_PCAP=).*,\1y,' .config
	sed -ri 's,(CONFIG_RTE_LIBRTE_IXGBE_ALLOW_UNSUPPORTED_SFP=).*,\1y,' .config
	cd ..
	make install T=x86_64-native-linuxapp-gcc EXTRA_CFLAGS="-fPIC"
	    
##2. Fetch and compile odp-dpdk
	git clone https://github.com/lvsgate/odp-dpdk.git <odp-dir>
	cd <odp-dir>
	./bootstrap
	./configure --with-platform=linux-dpdk --with-sdk-install-path=<dpdk-dir>/x86_64-native-linuxapp-gcc --prefix=<INSTALL ODP-DPDK TO THIS DIR> --enable-shared=n
	make
	make install
	
##3. Fetch and compile ofp
	yum install libnl3 libnl3-cli
	git clone https://github.com/lvsgate/ofp.git <ofp-dir>
	cd <ofp-dir>
	./bootstrap
	./configure --with-odp=<ODP-DPDK INSTALLATION DIR> --enable-shared=no --enable-sp=no
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
    ./ofp_vs -i 0,1 -c 3 -f ofp.conf # -i <port1>,<port2>  
                                     # -c <core count which include control core> 
                                     # -f <config file include default command which you can change in ofp cli>

## 7. Connect to ofp cli and configure network
    telnet localhost 2345
    type in "?" or "help"
    >>> ?
    # fp0 equal to port number 0 in dpdk
    >>> ifconfig fp0 <ip_addr>/<net_mask> 
    >>> ifconfig fp1 <ip_addr>/<net_mask> 
    >>> route add 0.0.0.0/0 gw <next hop> dev fp0
    >>> route add <ip_addr>/<net_mask> gw <next hop> dev fp1
    #flush flow director in fp1 (port 1 in dpdk)
    >>> fdir flush fp1 
    #Add flow director entry for binding local address <a.b.c.d> to queue <d%data_core_count>
    >>> fdir add fp1 proto ipv4 src_ipv4 0.0.0.0 src_port 0 dst_ipv4 192.168.210.100 dst_port 0 queue_id 0
    >>> fdir add fp1 proto ipv4 src_ipv4 0.0.0.0 src_port 0 dst_ipv4 192.168.210.101 dst_port 0 queue_id 1
    #You can add these commands above to startup config file ofp.conf


## 8. Use ipvsadm and keepalived to configure virtual server on ofp_vs
	#The usage is unchanged.
	#ipvsadm and keepalived will comunicate with ofp_vs process but not the kernel module.
	ipvsadm  -A  -t <vip:vport> -s rr
	ipvsadm  -a  -t <vip:vport> -r <rsip:rsport> -b
	ipvsadm  -P  -t <vip:vport> -z <local_addr>
	ipvsadm  -P  -t <vip:vport> -z <local_addr>
	ipvsadm -ln
	ipvadm -G
    
## 9. Try to visit vs now
	curl <vip:vport>

## 10. More details about ofp and odp-dpdk
    http://www.openfastpath.org/
    http://opendataplane.org/
    https://github.com/OpenFastPath/ofp

## 11. Support
	email: lvsgate@163.com  lvsgateservice@gmail.com
	QQ Group: 160148228
