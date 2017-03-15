#!/bin/sh
echo "Signing..."
dfuimagemaker/imagemaker -f EnclaveOS/main.bin -t EDOS -v 0x41 -e ffffffffffffffffffffff -q -p development -o signed_image.dfu
echo "Stitching..."
python generate_dfu_firmware.py STM32F1/build/enclave_stage1.bin signed_image.dfu qemu_image.bin