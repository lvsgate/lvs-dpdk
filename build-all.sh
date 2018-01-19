#!/bin/sh
ROOTDIR=`pwd`
DPDK_DIR=$ROOTDIR/dpdk
ODP_DPDK_DIR=$ROOTDIR/odp-dpdk
ODP_DPDK_INSTALL_DIR=$ROOTDIR/odp-dpdk/install
OFP_DIR=$ROOTDIR/ofp
OFP_VS_INSTALL_DIR=$ROOTDIR/ofp_vs
RTE_TARGET=x86_64-native-linuxapp-gcc

#Fetch and build dpdk
if [ ! -d $DPDK_DIR ]; then
    git clone git://dpdk.org/dpdk $DPDK_DIR
fi

if [ ! -d $DPDK_DIR/$RTE_TARGET ]; then
    cd $DPDK_DIR
    git pull
    git checkout v17.02
    make config T=$RTE_TARGET O=$RTE_TARGET
    cd $DPDK_DIR/$RTE_TARGET
    sed -ri 's,(CONFIG_RTE_LIBRTE_PMD_PCAP=).*,\1y,' .config
    sed -ri 's,(CONFIG_RTE_LIBRTE_PMD_OPENSSL=).*,\1y,' .config
    cd $DPDK_DIR
    make install T=$RTE_TARGET EXTRA_CFLAGS="-fPIC"
fi

if [ "$?" != "0" ]; then
    echo "Build dpdk error!"
    exit $?
fi

export RTE_SDK=$DPDK_DIR
export RTE_TARGET=$RTE_TARGET

#Fetch and build odp-dpdk
if [ ! -d $ODP_DPDK_DIR ]; then
    git clone  https://github.com/lvsgate/odp-dpdk.git $ODP_DPDK_DIR
fi

cd $ODP_DPDK_DIR
git pull

if [ ! -d $ODP_DPDK_INSTALL_DIR ]; then
    mkdir $ODP_DPDK_INSTALL_DIR
fi
./bootstrap
./configure --enable-shared --with-platform=linux-dpdk --enable-helper-linux --with-sdk-install-path=$DPDK_DIR/$RTE_TARGET --prefix=$ODP_DPDK_INSTALL_DIR

if [ "$?" != "0" ]; then
    echo "Configure odp-dpdk error!"
    exit $?
fi

make
make install
if [ "$?" != "0" ]; then
    echo "Build odp-dpdk error!"
    exit $?
fi


#Fetch and build ofp
yum install libnl3 libnl3-cli libnl3-devel
if [ ! -d $OFP_DIR ]; then
    git clone https://github.com/lvsgate/ofp.git $OFP_DIR
fi

cd $OFP_DIR
git pull
./bootstrap
./configure --with-odp-lib=odp-dpdk --with-odp=$ODP_DPDK_INSTALL_DIR --enable-shared=no --enable-sp=yes --disable-mtrie CPPFLAGS=-I$ODP_DPDK_INSTALL_DIR/include/odp/arch/x86_64-linux/

if [ "$?" != "0" ]; then
    echo "Configure ofp error!"
    exit $?
fi

make

if [ ! -d $OFP_VS_INSTALL_DIR ]; then
    mkdir $OFP_VS_INSTALL_DIR
fi

cp $OFP_DIR/example/ofp_vs/ofp_vs $OFP_VS_INSTALL_DIR
cp $OFP_DIR/example/ofp_vs/ofp.conf $OFP_VS_INSTALL_DIR
cp $OFP_DIR/example/ofp_vs/start.sh $OFP_VS_INSTALL_DIR


if [ "$?" != "0" ]; then
    echo "Build ofp error!"
    exit $?
fi


#Fetch and build lvs-dpdk tools
cd $ROOTDIR/tools/keepalived
sh configure --prefix=/usr --sysconfdir=/etc/ CPPFLAGS=-I/usr/include/libnl3/ LDFLAGS=-L/usr/lib64/
make
make install
if [ "$?" != "0" ]; then
    echo "Build keepalived error!"
    exit $?
fi

cd $ROOTDIR/tools/ipvsadm
make
make install
if [ "$?" != "0" ]; then
    echo "Build ipvsadm error!"
    exit $?
fi
