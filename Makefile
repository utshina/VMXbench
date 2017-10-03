CC = x86_64-w64-mingw32-gcc
CFLAGS = -std=gnu11 -ffreestanding -shared -nostdlib -Wall -Werror \
	 -fno-stack-check -fno-stack-protector \
	 -mno-stack-arg-probe -mno-red-zone -mno-sse -mno-ms-bitfields \
         -Wl,--subsystem,10 \
         -e EfiMain \
         -O6

QEMU = qemu-system-x86_64
QEMU_DISK = 'json:{ "fat-type": 0, "dir": "image", "driver": "vvfat", "floppy": false, "rw": true }'
QEMU_OPTS =-nodefaults -machine accel=kvm -cpu host -m 128 -bios OVMF.fd -hda $(QEMU_DISK) -nographic -serial mon:stdio -no-reboot

NESTED=$(shell cat /sys/module/kvm_intel/parameters/nested)
ifeq ($(NESTED),N)
	ENABLE_NESTED=enable_nested
else
	ENABLE_NESTED=
endif

%.efi: %.c
	$(CC) $(CFLAGS) $< -o $@

.PHONY: all enable_nested disable_nested qemu clean


all: main.efi

qemu: OVMF.fd image/EFI/BOOT/BOOTX64.EFI $(ENABLE_NESTED)
	$(QEMU) $(QEMU_OPTS)

OVMF.fd:
	wget http://downloads.sourceforge.net/project/edk2/OVMF/OVMF-X64-r15214.zip
	unzip OVMF-X64-r15214.zip OVMF.fd
	rm OVMF-X64-r15214.zip

image/EFI/BOOT/BOOTX64.EFI: main.efi
	mkdir -p image/EFI/BOOT
	ln -sf ../../../main.efi image/EFI/BOOT/BOOTX64.EFI

enable_nested:
	@echo Enabling nested virtualization in KVM ...
	sudo modprobe -r kvm_intel;
	sudo modprobe kvm_intel nested=1;

disable_nested:
	@echo Disabling nested virtualization in KVM ...
	sudo modprobe -r kvm_intel;
	sudo modprobe kvm_intel nested=0;

clean:
	rm -f main.efi OVMF.fd
	rm -rf image
