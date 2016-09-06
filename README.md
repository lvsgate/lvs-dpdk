# lvs-dpdk

This project has ported LVS-FULLNAT to OpenFastPath(base on odp-dpdk).

LVS-FULLNAT origin source code is from https://github.com/alibaba/LVS

OpenFastPath source code is on https://github.com/lvsgate/ofp.git

# Build steps
##1. Get and compile OpenFastPath
    The ofp depend on odp-dpdk (https://git.linaro.org/lng/odp-dpdk.git)
		See the documents on https://github.com/lvsgate/ofp.git

##2. Get lvs-dpdk source code
		git clone https://github.com/lvsgate/lvs-dpdk.git

## 3. Copy ofp_vs to ofp/examples/ofp_vs
		cd $(topdir)/ofp/examples
		cp -r $(topdir)/lvs-dpdk/ofp_vs ./
			

##4. Compile ofp_vs 
		cd $(topdir)/ofp/examples/ofp_vs
		make

## 5. Compile keepalived
  	cd $(topdir)/lvs-dpdk/tools/keepalived
		./configure
		make
		make install

## 6. Compile ipvsadm
		cd $(topdir)/lvs-dpdk/tools/ipvsadm
		make
		make install
		
## 7. Configure ofp_vs
    Edit ofp_vs/ofp.conf
    
## 8. Run ofp_vs
    ./start.sh

## 9. Telnet and Configure
    telnet localhost 2345
    type in help for more infomation

## 10. More details
    http://www.openfastpath.org/
    https://github.com/OpenFastPath/ofp
