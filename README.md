Enclave Bootloader + OS src tree
================================

Getting started
---------------

#### Building
All the custom build scripts are for Windows and hackily refernce CLI tools such as Make statically. However, the all main arm-none-eabi-* toolchain building should be pretty standard for any OS.

##### General build option
QEMU_BUILD=1 --- Build bootloader for QEMU

DEBUG=1 	 --- Enables UART output along with a few other debug operations

#### QEMU Build Routine
Make sure you're linking against the qemu.ld script in both the STM32F1 and EnclaveOS subprojects and QEMU_BUILD=1 is set in STM32F1/hardware.h

The bootloader want an ECID at runtime for signature validation, using ```dfuimagemaker``` just include the -e arguement with all F's. This will sign the firmware for that the QEMU ECID, on QEMU builds the ECID is set to 'FFFFFFFFFFFFFFFFFFFFFFF' and slaps it in an image container 

e.g
```dfuimagemaker/imagemaker -f EnclaveOS/main.bin -t EDOS -v 0x41 -e FFFFFFFFFFFFFFFFFFFFFFF -p development -o signed_image.dfu```

Now you need to stitch the main OS to the bootloader with ```generate_dfu_firmware.py``` 

e.g 
```python generate_dfu_firmware.py STM32F1/build/enclave_stage1.bin signed_image.dfu qemu_image.bin```

Our bootloader lives in flash at ```0x00000000``` 

Our main OS lives in flash at ```0x00008000``` 