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

void NMI_Handler(void) {
}





void SVC_Handler(void) {
}

void DebugMon_Handler(void) {
}

void PendSV_Handler(void) {
}

uint32_t msTicks = 0;                                       /* Variable to store millisecond ticks */
                                            
void SysTick_Handler(void)  {                               
  msTicks++;                                                   
}
