/*
 * Interrupt vector prototypes go here. Just add any you need.
 * A full list of possible vectors is in lib/CMSIS_CM3/startup/gcc/stm32f10x_*.s
 * You can also put the interrupt vector anywhere that gets compiled in,
 * including one source file per interrupt, in main.c, etc. Be sure to keep
 * the ones listed here, though.
 */

#ifndef __INTERRUPTS_H
#define __INTERRUPTS_H

#include "stm32f10x.h"

void NMI_Handler(void)__attribute__ ( ( naked ) );
void SVC_Handler(void)__attribute__ ( ( naked ) );
void DebugMon_Handler(void)__attribute__ ( ( naked ) );
void PendSV_Handler(void)__attribute__ ( ( naked ) );
void SysTick_Handler(void)__attribute__ ( ( naked ) );
void HardFault_Handler(void) __attribute__ ( ( naked ) );
void MemManage_Handler(void) __attribute__ ( ( naked ) );
void UsageFault_Handler(void) __attribute__ ( ( naked ) );
#endif //__INTERRUPTS_H