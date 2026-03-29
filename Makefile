obj-m += syscall_monitor.o

KDIR := /lib/modules/$(shell uname -r)/build

ccflags-y := -Wall -Wextra

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean

load:
	sudo insmod syscall_monitor.ko target_uid=$(shell id -u)

unload:
	sudo rmmod syscall_monitor

log:
	cat /proc/syscall_monitor

stats:
	@echo 'open_count  :' $$(cat /sys/kernel/syscall_monitor/open_count)
	@echo 'execve_count:' $$(cat /sys/kernel/syscall_monitor/execve_count)
	@echo 'enabled     :' $$(cat /sys/kernel/syscall_monitor/enabled)
	@echo 'target_uid  :' $$(cat /sys/kernel/syscall_monitor/target_uid)
