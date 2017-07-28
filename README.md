# lvs-dpdk

This project has ported LVS FULLNAT/DR/NAT and SNAT-GATEWAY to OpenFastPath(base on odp-dpdk).

NAT is only available on single core while FULLNAT,DR and SNAT-GATEWAY support multi-cores, because in lvs-dpdk each core has one local session table and depend on flow director.

LVS-FULLNAT origin source code is at https://github.com/alibaba/LVS

LVS-SNAT gateway origin source code is at https://github.com/jlijian3/lvs-snat

I had forked OpenFastPath project and added ofp_vs example, see https://github.com/lvsgate/ofp.git

I had forked odp-dpdk project and added support for flow director, see https://github.com/lvsgate/odp-dpdk.git

Please note that this project only had limited testing.

# Prerequisites

- Intel x86 CPU
- NIC which support flow director, if you want to run on multi-cores
- lvs-dpdk has been compiled and tested on Centos 7.2 with 3.10 kernel

# Build steps

## 1. Fetch and compile DPDK

	git clone git://dpdk.org/dpdk ./<dpdk-dir>
	cd <dpdk-dir>
	git checkout -b 17.02 tags/v17.02
	make config T=x86_64-native-linuxapp-gcc O=x86_64-native-linuxapp-gcc
	cd <dpdk-dir>/x86_64-native-linuxapp-gcc
    sed -ri 's,(CONFIG_RTE_LIBRTE_PMD_PCAP=).*,\1y,' .config
    sed -ri 's,(CONFIG_RTE_LIBRTE_PMD_OPENSSL=).*,\1y,' .config
	cd ..
	make install T=x86_64-native-linuxapp-gcc EXTRA_CFLAGS="-fPIC"
	
	#Add env value
	export RTE_SDK=<dpdk-dir>
    export RTE_TARGET=x86_64-native-linuxapp-gcc
	    
## 2. Fetch and compile odp-dpdk

	git clone  https://github.com/lvsgate/odp-dpdk.git <odp-dir>
	cd <odp-dir>
	./bootstrap
	./configure --with-platform=linux-dpdk --with-sdk-install-path=<dpdk-dir>/x86_64-native-linuxapp-gcc --prefix=<INSTALL ODP-DPDK TO THIS DIR>
	make
	make install
	
## 3. Fetch and compile ofp

	yum install libnl3 libnl3-cli libnl3-devel
	git clone https://github.com/lvsgate/ofp.git <ofp-dir>
	cd <ofp-dir>
	./bootstrap
	./configure --with-odp-lib=odp-dpdk --with-odp=<ODP-DPDK INSTALLATION DIR> --enable-shared=no --enable-sp=yes --disable-mtrie CXXFLAGS=-I<ODP-DPDK INSTALLATION DIR>/include/odp/arch/x86_64-linux/
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

## 5. Prepare DPDK for running lvs-dpdk
	echo 2048 > /sys/devices/system/node/node0/hugepages/hugepages-2048kB/nr_hugepages
	mkdir /mnt/huge
	mount -t hugetlbfs nodev /mnt/huge
	modprobe uio
	insmod <dpdk-dir>/x86_64-native-linuxapp-gcc/kmod/igb_uio.ko
	cd <dpdk-dir>
	./usertools/dpdk-devbind.py --status
	./usertools/dpdk-devbind.py --bind=igb_uio <pci-id-1>
	./usertools/dpdk-devbind.py --bind=igb_uio <pci-id-2>

		
## 6. Run lvs-dpdk
    modprobe ip_vs  #add this line to /etc/rc.local, because ipvsadm and keepalived depend on it.
    cd <ofp-dir>/examples/ofp_vs
    ./ofp_vs -i 0,1 -c 2 -o 0 -p 1 -f ofp.conf # -i <port1>,<port2>  
                                     # -c <worker core count> 
                                     # -o <outer port to wan, snat-gw fdir rule will be add to this port>
                                     # -p <inner port to lan, fullnat fdir rule  will be add to this port>
                                     # -f <config file include default command which you can change in ofp cli>
    #If worker core count > 0, -o is required for snat-gw, -p is required for fullnat.


## 7. Connect to ofp cli or edit ofp.conf to configure network
    telnet localhost 2345
    type in "?" or "help"
    >>> ?
    # fp0 equal to port number 0 in dpdk
    >>> ifconfig fp0 <ip_addr>/<net_mask> 
    >>> ifconfig fp1 <ip_addr>/<net_mask> 
    #default gw don't work if enable mtries routing, may be ofp's bug.
    >>> route add 0.0.0.0/0 gw <next hop> dev fp0
    >>> route add <ip_addr>/<net_mask> gw <next hop> dev fp1
    
    
## 9. Connect to ofp or edit ofp.conf to configure SNAT-GATEWAY
    telnet localhost 2345
    >>> snat enable
    >>> snat add from 10.1.0.0/16 to 0.0.0.0/0 out_dev fp0 source 192.168.50.253 - 192.168.50.253 algo sd
    >>> snat add from 10.1.0.10/32 to 0.0.0.0/0 out_dev fp0 source 192.168.50.100 - 192.168.50.103 algo sdfn
    >>> snat del from 10.1.0.10/32 to 0.0.0.0/0 out_dev fp0
    >>> snat show
    

## 10. Use ipvsadm and keepalived to configure virtual server on ofp_vs
	#The usage is unchanged.
	#ipvsadm and keepalived will comunicate with ofp_vs process but not the kernel module.
	#Create FULLNAT virtual server, local address count must be greater than worker count
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
