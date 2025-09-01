#!/bin/bash

# This script performs the following steps:
# 1. Setup hugepages.
# 2. Load the necessary kernel modules to access the NIC using DPDK library.
# 3. Bind the ethernet device(s) to the specified kernel module.

load_kernel_module () {
	if [ $# != 1 ]; then
		echo "Invalid number of arguments passed.";
		return 1;
	fi

	echo "Loading kernel module: $1";

	if [ $1 == "vfio-pci" ];then
		sudo lsmod | grep "\bvfio_pci\b" > /dev/null 2>&1
	else
		sudo lsmod | grep "\b$1\b" > /dev/null 2>&1
	fi

	if [ $? != 0 ]; then
		sudo modprobe $1
		if [ $? != 0 ]; then
			echo "Unable to load kernel module: $1"
			return 1;
		fi
	else
		echo "Kernel module: $1 already loaded."
	fi

	return 0
}

DPDK_HOME=$HOME/dpdk-stable
DPDK_USER_TOOLS_DIR=$DPDK_HOME/usertools

if [ ! -d "$DPDK_USER_TOOLS_DIR" ]; then
	echo "Directory '$DPDK_USER_TOOLS_DIR' doesn't exists. Exiting ..."
	exit 1
fi

cd $DPDK_USER_TOOLS_DIR

echo "Mounting huge pages ... "
sudo ./dpdk-hugepages.py --pagesize 1G --setup 2G --node 0
if [ $? != 0 ]; then
	echo "Unable to mount hugepages. Exiting ..."
	exit 2
fi
echo "Done."
echo ""

echo "Loading kernel modules ..."
load_kernel_module uio
if [ $? != 0 ]; then
	exit 3
fi

load_kernel_module uio_pci_generic
if [ $? != 0 ]; then
        exit 3
fi

load_kernel_module vfio-pci
if [ $? != 0 ]; then
        exit 3
fi
echo "Done. "
echo ""


bind_device_to_dpdk_driver () {
	if [ $# != 1 ]; then
                echo "Invalid number of arguments passed to bind_device function. ";
                return 4;
        fi
	
	echo "Binding ethernet device(s) "$1" to DPDK driver ..."
	sudo ./dpdk-devbind.py -b vfio-pci "$1" --force
	if [ $? != 0 ]; then
        	echo "Unable to bind ethernet device "$1" to DPDK driver. Exiting ..."
        	exit 4
	fi
	echo "Done."
}

bind_device_to_dpdk_driver "0000:04:00.0"
bind_device_to_dpdk_driver "0000:04:00.1"

