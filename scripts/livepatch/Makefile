hostprogs			:= klp-convert
always-y			:= $(hostprogs)

klp-convert-objs		:= klp-convert.o elf.o

HOST_EXTRACFLAGS		:= -g -I$(INSTALL_HDR_PATH)/include -Wall
HOSTLDLIBS_klp-convert		:= -lelf
