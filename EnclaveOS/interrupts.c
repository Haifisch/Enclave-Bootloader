/*
* Interrupt vector implementations go here. Just add any you need.
* A full list of possible vectors is in lib/CMSIS_CM3/startup/gcc/stm32f10x_*.s
* You can also put the interrupt vector anywhere that gets compiled in,
* including one source file per interrupt, in main.c, etc. Be sure to keep
* the ones listed here, though.
*/

#include "interrupts.h"
#include "printf_uart.h"
/* The following interrupts should be present, though you can of course
 * modify them as required.
 */
enum { r0, r1, r2, r3, r12, lr, pc, psr};

static void printUsageErrorMsg(uint32_t CFSRValue)
{
   debug_print("Usage fault: \n");
   CFSRValue >>= 16; // right shift to lsb

   if((CFSRValue & (1<<9)) != 0) {
      debug_print("Divide by zero\n");
   }
   if((CFSRValue & (1<<8)) != 0) {
      debug_print("Unaligned access\n");
   }
}

static void printBusFaultErrorMsg(uint32_t CFSRValue)
{
  static char buf[200];
  debug_print("Bus fault: \r\n");

  if((CFSRValue & (1 << 0)) == (1 << 0)) //IACCVIOL
    debug_print("-->Instruction access violation\r\n");

  if((CFSRValue & (1 << 1)) == (1 << 1)) //DACCVIOL
    debug_print("-->Data access violation\r\n");

  if((CFSRValue & (1 << 8)) == (1 << 8)) //IBUSERR
    debug_print("-->Instruction bus error\r\n");

  if((CFSRValue & (1 << 9)) == (1 << 9)) //PRECISERR
    debug_print("-->Precise data bus error\r\n");

  if((CFSRValue & (1 << 10)) == (1 << 10)) //PRECISERR
    debug_print("-->Imprecise data bus error\r\n");

  if((CFSRValue & (1 << 11)) == (1 << 11)) //UNSTKERR
    debug_print("-->Bus fault on unstacking for a return from exception\r\n");

  if((CFSRValue & (1 << 12)) == (1 << 12)) //STKERR
   debug_print("-->Bus fault on stacking for exception entry\r\n");

  if((CFSRValue & (1 << 13)) == (1 << 13)) //LSPERR
    debug_print("-->Bus fault on floating-point lazy state preservation\r\n");

  if((CFSRValue & (1 << 15)) == (1 << 15)) //BFARVALID
  {
    debug_print("-->Bus fault adress register valid\r\n");
    sprintf(buf, "----> 0x%08X <------ Fault address\r\n", SCB->BFAR);
    debug_print(buf);
  }
}

static void printMemoryManagementErrorMsg(uint32_t CFSRValue)
{
   debug_print("Memory Management fault: \n");
   CFSRValue &= 0x000000FF; // mask just mem faults
   if((CFSRValue & (1<<5)) != 0) {
      debug_print("A MemManage fault occurred during FP lazy state preservation\n");
   }
   if((CFSRValue & (1<<4)) != 0) {
      debug_print("A derived MemManage fault occurred on exception entry\n");
   }
   if((CFSRValue & (1<<3)) != 0) {
      debug_print("A derived MemManage fault occurred on exception return.\n");
   }
   if((CFSRValue & (1<<1)) != 0) {
      debug_print("Data access violation.\n");
   }
   if((CFSRValue & (1<<0)) != 0) {
      debug_print("MPU or Execute Never (XN) default memory map access violation\n");
   }
   if((CFSRValue & (1<<7)) != 0) {
      static char msg[80];
      sprintf(msg, "SCB->MMFAR = 0x%08x\n", SCB->MMFAR );
      debug_print(msg);
   }
}
static void stackDump(uint32_t stack[])
{
   static char msg[80];
   sprintf(msg, "R0  = 0x%08x\n", stack[r0]);  debug_print(msg);
   sprintf(msg, "R1  = 0x%08x\n", stack[r1]);  debug_print(msg);
   sprintf(msg, "R2  = 0x%08x\n", stack[r2]);  debug_print(msg);
   sprintf(msg, "R3  = 0x%08x\n", stack[r3]);  debug_print(msg);
   sprintf(msg, "R12 = 0x%08x\n", stack[r12]); debug_print(msg);
   sprintf(msg, "LR  = 0x%08x\n", stack[lr]);  debug_print(msg);
   sprintf(msg, "PC  = 0x%08x\n", stack[pc]);  debug_print(msg);
   sprintf(msg, "PSR = 0x%08x\n", stack[psr]); debug_print(msg);
}

void hard_fault_handler_c (unsigned int * hardfault_args)
{
  volatile unsigned long stacked_r0 ;
  volatile unsigned long stacked_r1 ;
  volatile unsigned long stacked_r2 ;
  volatile unsigned long stacked_r3 ;
  volatile unsigned long stacked_r12 ;
  volatile unsigned long stacked_lr ;
  volatile unsigned long stacked_pc ;
  volatile unsigned long stacked_psr ;
  volatile unsigned long _CFSR ;
  volatile unsigned long _HFSR ;
  volatile unsigned long _DFSR ;
  volatile unsigned long _AFSR ;
  volatile unsigned long _BFAR ;
  volatile unsigned long _MMAR ;
 
  stacked_r0 = ((unsigned long)hardfault_args[0]) ;
  stacked_r1 = ((unsigned long)hardfault_args[1]) ;
  stacked_r2 = ((unsigned long)hardfault_args[2]) ;
  stacked_r3 = ((unsigned long)hardfault_args[3]) ;
  stacked_r12 = ((unsigned long)hardfault_args[4]) ;
  stacked_lr = ((unsigned long)hardfault_args[5]) ;
  stacked_pc = ((unsigned long)hardfault_args[6]) ;
  stacked_psr = ((unsigned long)hardfault_args[7]) ;
 
  // Configurable Fault Status Register
  // Consists of MMSR, BFSR and UFSR
  _CFSR = (*((volatile unsigned long *)(0xE000ED28))) ;
 
  // Hard Fault Status Register
  _HFSR = (*((volatile unsigned long *)(0xE000ED2C))) ;
 
  // Debug Fault Status Register
  _DFSR = (*((volatile unsigned long *)(0xE000ED30))) ;
 
  // Auxiliary Fault Status Register
  _AFSR = (*((volatile unsigned long *)(0xE000ED3C))) ;
 
  // Read the Fault Address Registers. These may not contain valid values.
  // Check BFARVALID/MMARVALID to see if they are valid values
  // MemManage Fault Address Register
  _MMAR = (*((volatile unsigned long *)(0xE000ED34))) ;
  // Bus Fault Address Register
  _BFAR = (*((volatile unsigned long *)(0xE000ED38))) ;
  __asm("BKPT #0\n") ; // Break into the debugger
}
 
void panic() {
  uart_printf("panic() called!\n");
  __asm("MOV r0, sp");
  __asm("BL hard_fault_handler_c");
  //DEBUG_PRINTLN("Panic reason; %s\n", reason);
  //DEBUG_PRINTLN("Panic caller; %s\n", caller);
  //DEBUG_PRINTLN("Line number; %i", lineNumber);
  while (1); // hang for panic, PROD devices should reset
}

void Hard_Fault_Handler(uint32_t stack[]) {
  static char msg[80];
  //if((CoreDebug->DHCSR & 0x01) != 0) {
  debug_print("\nIn Hard Fault Handler\n");
  sprintf(msg, "SCB->HFSR = 0x%08x\n", SCB->HFSR);
  debug_print(msg);
  if ((SCB->HFSR & (1 << 30)) != 0) {
     debug_print("Forced Hard Fault\n");
     sprintf(msg, "SCB->CFSR = 0x%08X\n", SCB->CFSR );
     debug_print(msg);
     if((SCB->CFSR & 0xFFFF0000) != 0) {
        printUsageErrorMsg(SCB->CFSR);
     } 
     if((SCB->CFSR & 0xFF00) != 0) {
        printBusFaultErrorMsg(SCB->CFSR);
     }
     if((SCB->CFSR & 0xFF) != 0) {
        printMemoryManagementErrorMsg(SCB->CFSR);
     } 
  }
  stackDump(stack);
  __ASM volatile("BKPT #01");
  while(1);
}

void __attribute__((naked)) HardFault_Handler(void)
{
   __asm("TST lr, #4");
   __asm("ITE EQ");
   __asm("MRSEQ r0, MSP");
   __asm("MRSNE r0, PSP");
   __asm("B Hard_Fault_Handler");
}
void NMI_Handler(void) {
  debug_print("NMI fault!\n");
  __asm("TST lr, #4");
  __asm("ITE EQ \n"
       "MRSEQ r0, MSP \n"
       "MRSNE r0, PSP");
  __asm("B Hard_Fault_Handler");
}

void SVC_Handler(void) {
  __asm("TST lr, #4");
  __asm("ITE EQ \n"
       "MRSEQ r0, MSP \n"
       "MRSNE r0, PSP");
  __asm("B Hard_Fault_Handler");
}

void DebugMon_Handler(void) {
  debug_print("Debug monitor fault!\n");
  __asm("TST lr, #4");
  __asm("ITE EQ \n"
       "MRSEQ r0, MSP \n"
       "MRSNE r0, PSP");
  __asm("B Hard_Fault_Handler");
}

void PendSV_Handler(void) {
  panic();
}

void __attribute__((naked)) MemManage_Handler(void) {
  debug_print("Memory access fault!\n");
  __asm("TST lr, #4");
  __asm("ITE EQ \n"
       "MRSEQ r0, MSP \n"
       "MRSNE r0, PSP");
  __asm("B Hard_Fault_Handler");
}

void __attribute__((naked)) BusFault_Handler(void) {
  debug_print("Bus fault!\n");
  __asm("TST lr, #4");
  __asm("ITE EQ \n"
       "MRSEQ r0, MSP \n"
       "MRSNE r0, PSP");
  __asm("B Hard_Fault_Handler");
}

void __attribute__((naked)) UsageFault_Handler(void) {
  debug_print("Usage fault!\n");
  __asm("TST lr, #4");
  __asm("ITE EQ \n"
       "MRSEQ r0, MSP \n"
       "MRSNE r0, PSP");
  __asm("B Hard_Fault_Handler");
}

uint32_t msTicks = 0;                                       /* Variable to store millisecond ticks */
                                        
void SysTick_Handler(void)  {                               
  msTicks++;                                                   
}
