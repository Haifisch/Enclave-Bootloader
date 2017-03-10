cd STM32F1
del build\*.o
del build\enclave_stage1.*
C:\Users\haifisch\Downloads\android-ndk-r13b-windows-x86_64\android-ndk-r13b\prebuilt\windows-x86_64\bin\make generic-pc13
cd ../EnclaveOS
del main.bin main.elf main.bin.dfu.bin main.map
C:\Users\haifisch\Downloads\android-ndk-r13b-windows-x86_64\android-ndk-r13b\prebuilt\windows-x86_64\bin\make DEBUG=1
cd ../