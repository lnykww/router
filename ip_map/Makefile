obj-m += ip_map.o
ip_map-objs := mapping.o
 
all:
	    make -C /lib/modules/$(shell uname -r)/build M=$(shell pwd) modules
clean:
	    make -C /lib/modules/$(shell uname -r)/build M=$(shell pwd) clean
