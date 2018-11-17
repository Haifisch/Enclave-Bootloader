# QEMU Configuration
QEMU_BUILD_DIRECTORY = ../qemu/arm-softmmu
QEMU_TARGET_IMAGE = STM32F1/build/enclave_stage1.bin
QEMU_MACHINE = stm32-p103

# building
build-bl:
	@echo "Building bootloader"
	@cd STM32F1; make generic-pc13 

build-os:
	@echo "Building OS"
	@cd EnclaveOS; make 

# running within qemu
run-bl:
	@echo "Running bootloader in qemu"
	#$(QEMU_BUILD_DIRECTORY)/qemu-system-arm -M $(QEMU_BOARD_OPT) -nographic -kernel $(QEMU_TARGET_IMAGE)
	$(QEMU_BUILD_DIRECTORY)/qemu-system-arm -machine $(QEMU_MACHINE) -nographic -kernel $(QEMU_TARGET_IMAGE)

# clean up
clean-os:
	@echo "Cleaning out old OS builds"

clean-bl:
	@echo "Cleaning out old bootloader builds"
	@rm -rf STM32F1/.dep/*
	@rm -rf STM32F1/build/*.o 
	@rm -rf STM32F1/build/enclave_stage1.*

# alias cleaning
clean-all: clean-bl clean-os 

# alias building
build-all-bl: clean-bl build-bl
build-all-os: clean-os build-os
build-all: build-all-bl build-all-os

all: clean-all build-all

