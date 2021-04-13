PB_CCFLAGS := -DPB_SYSTEM_HEADER="<pbsystem.h>" \
	-DPB_NO_ERRMSG \
	-DPB_FIELD_16BIT \
	-DPB_BUFFER_ONLY
export PB_CCFLAGS

subdir-$(CONFIG_SECURITY_CONTAINER_MONITOR) += protos

obj-$(CONFIG_SECURITY_CONTAINER_MONITOR) += protos/
obj-$(CONFIG_SECURITY_CONTAINER_MONITOR) += monitor.o pb.o process.o vsock.o

ccflags-y := -I$(srctree)/security/container/protos \
	-I$(srctree)/security/container/protos/nanopb \
	-I$(srctree)/fs \
	$(PB_CCFLAGS)
ccflags-$(CONFIG_SECURITY_CONTAINER_MONITOR_DEBUG) += -DDEBUG
