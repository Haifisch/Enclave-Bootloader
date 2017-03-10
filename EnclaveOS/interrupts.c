/*
* Interrupt vector implementations go here. Just add any you need.
* A full list of possible vectors is in lib/CMSIS_CM3/startup/gcc/stm32f10x_*.s
* You can also put the interrupt vector anywhere that gets compiled in,
* including one source file per interrupt, in main.c, etc. Be sure to keep
* the ones listed here, though.
*/

#include "interrupts.h"

/* The following interrupts should be present, though you can of course
 * modify them as required.
 */

void hard_fault_handler_c (unsigned int * hardfault_args)
{
  uart_printf("handling fault\n");
  unsigned int stacked_r0;
  unsigned int stacked_r1;
  unsigned int stacked_r2;
  unsigned int stacked_r3;
  unsigned int stacked_r4;
  unsigned int stacked_r5;
  unsigned int stacked_r10;
  unsigned int stacked_r11;  
  unsigned int stacked_r12;
  unsigned int stacked_lr;
  unsigned int stacked_pc;
  unsigned int stacked_psr;

  stacked_r0 = ((unsigned long) hardfault_args[0]);
  stacked_r1 = ((unsigned long) hardfault_args[1]);
  stacked_r2 = ((unsigned long) hardfault_args[2]);
  stacked_r3 = ((unsigned long) hardfault_args[3]);
  stacked_r4 = ((unsigned long) hardfault_args[4]);
  stacked_r5 = ((unsigned long) hardfault_args[5]);
  stacked_r10 = ((unsigned long) hardfault_args[10]);
  stacked_r11 = ((unsigned long) hardfault_args[11]);
  stacked_r12 = ((unsigned long) hardfault_args[4]);
  stacked_lr = ((unsigned long) hardfault_args[5]);
  stacked_pc = ((unsigned long) hardfault_args[6]);
  stacked_psr = ((unsigned long) hardfault_args[7]);


  uart_printf("R0 = 0x%x\t\tR1 = 0x%x\n", stacked_r0, stacked_r1);
  uart_printf("R2 = 0x%x\t\tR3 = 0x%x\n", stacked_r2, stacked_r3);
  uart_printf("R4 = 0x%x\t\tR5 = 0x%x\n", stacked_r4, stacked_r5);
  uart_printf("R10 = 0x%x\tR11 = 0x%x\n", stacked_r10, stacked_r11);
  uart_printf("R12 =0x%x\t\tPSR = 0x%x\n", stacked_r12, stacked_psr);
  uart_printf("LR [R14] = 0x%x  subroutine call return address\n", stacked_lr);
  uart_printf("PC [R15] = 0x%x  program counter\n", stacked_pc);
  uart_printf ("BFAR = 0x%x\tCFSR = 0x%x\n", (*((volatile unsigned long *)(0xE000ED38))), (*((volatile unsigned long *)(0xE000ED28))));
  uart_printf ("HFSR = 0x%x\t\tDFSR = 0x%x\n", (*((volatile unsigned long *)(0xE000ED2C))), (*((volatile unsigned long *)(0xE000ED30))));
  uart_printf ("AFSR = 0x%x\t\tSCB_SHCSR = 0x%x\n", (*((volatile unsigned long *)(0xE000ED3C))), SCB->SHCSR);

  while (1);
}

void HardFault_Handler(void) {
  __asm("BL hard_fault_handler_c");
}

void NMI_Handler(void) {
	__asm("BL hard_fault_handler_c");
}


void SVC_Handler(void) {
	__asm("BL hard_fault_handler_c");
}

void DebugMon_Handler(void) {
	__asm("BL hard_fault_handler_c");
}

void PendSV_Handler(void) {
	__asm("BL hard_fault_handler_c");
}

uint32_t msTicks = 0;                                       /* Variable to store millisecond ticks */
                                            
void SysTick_Handler(void)  {                               
  msTicks++;                                                   
}
