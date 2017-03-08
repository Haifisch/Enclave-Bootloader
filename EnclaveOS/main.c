/*
 * Copyright (C) 2016-2017 Sun Tzu Security, LLC. All rights reserved.
 *
 * This document is the property of Sun Tzu Security, LLC.
 * It is considered confidential and proprietary.
 *
 * This document may not be reproduced or transmitted in any form,
 * in whole or in part, without the express written permission of
 * Sun Tzu Security, LLC.
 */

#define TINYPRINTF_DEFINE_TFP_PRINTF 1
#define TINYPRINTF_DEFINE_TFP_SPRINTF 0
#define TINYPRINTF_OVERRIDE_LIBC 0

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <limits.h>
#include <unistd.h>
#include <errno.h>
#include <stdarg.h>
// Load CMSIS and peripheral library and configuration
#include "stm32f10x.h"
#include "aes.h"
#include "tests.h"
#include "curve25519.h"
#include "interrupts.h"
#include "sha256.h"
#include "div.h"
void GPIO_Config();

void UU_PutChar(USART_TypeDef* USARTx, uint8_t ch)
{
  while(!(USARTx->SR & USART_SR_TXE));
  USARTx->DR = ch;  
}

void UU_PutString(USART_TypeDef* USARTx, uint8_t * str)
{
  while(*str != 0)
  {
    UU_PutChar(USARTx, *str);
    str++;
  }
}

void vprint(const char *fmt, va_list argp)
{
    char string[200];
    if(0 < vsprintf(string,fmt,argp)) // build string
    {
        UU_PutString(USART1, (uint8_t*)string); // send message via UART

    }
}

void uart_printf(const char *fmt, ...) // custom printf() function
{
    va_list argp;
    va_start(argp, fmt);
    vprint(fmt, argp);
    va_end(argp);
}

#define DEBUG_PRINTLN(x, ...) \
        if (DEBUG) { uart_printf(x, ## __VA_ARGS__); } 

// A simple busy wait loop
void Delay(volatile unsigned long delay);

void usart_init(void)
{
    GPIO_InitTypeDef GPIO_InitStructure;
    USART_InitTypeDef USART_InitStructure; 
    USART_ClockInitTypeDef USART_ClockInitStructure;
     
    //enable bus clocks
    RCC_APB2PeriphClockCmd(RCC_APB2Periph_USART1 | RCC_APB2Periph_GPIOA | RCC_APB2Periph_AFIO, ENABLE);
     
    //Set USART1 Tx (PA.09) as AF push-pull
    GPIO_InitStructure.GPIO_Pin = GPIO_Pin_9;  
    GPIO_InitStructure.GPIO_Mode = GPIO_Mode_AF_PP;   
    GPIO_InitStructure.GPIO_Speed = GPIO_Speed_50MHz;
     
    GPIO_Init(GPIOA, &GPIO_InitStructure);
     
    //Set USART1 Rx (PA.10) as input floating
     
    GPIO_InitStructure.GPIO_Pin = GPIO_Pin_10;
     
    GPIO_InitStructure.GPIO_Mode = GPIO_Mode_IN_FLOATING;
     
    GPIO_Init(GPIOA, &GPIO_InitStructure);
     
    USART_ClockStructInit(&USART_ClockInitStructure);
     
    USART_ClockInit(USART1, &USART_ClockInitStructure);
     
    USART_InitStructure.USART_BaudRate = 115200;     
    USART_InitStructure.USART_WordLength = USART_WordLength_8b;     
    USART_InitStructure.USART_StopBits = USART_StopBits_1;     
    USART_InitStructure.USART_Parity = USART_Parity_No ;    
    USART_InitStructure.USART_Mode = USART_Mode_Rx | USART_Mode_Tx;    
    USART_InitStructure.USART_HardwareFlowControl = USART_HardwareFlowControl_None;
     
    //Write USART1 parameters     
    USART_Init(USART1, &USART_InitStructure);
     
    //Enable USART1
    USART_Cmd(USART1, ENABLE);
 
}

void print_hash(unsigned char hash[])
{
   int idx;
   for (idx=0; idx < 32; idx++)
      uart_printf("%02x",hash[idx]);
   uart_printf("\n");
}

void printVersionHeader() {
  uart_printf("=====================================\n");
  uart_printf("::Enclave OS\n");
  uart_printf("::Copyright Sun Tzu Security LLC 2016-2017\n");
  uart_printf("::BUILD_DATE: " __DATE__ "\n");
  uart_printf("::BUILD_TAG: DEBUG\n");
  uart_printf("=====================================\n");
}

void MemManage_Handler(void) {
        uart_printf("got fault!\n");
    /* Go to infinite loop when Memory Manage exception occurs */
    while (1);
}

void BusFault_Handler(void) {
        uart_printf("got fault!\n");
    /* Go to infinite loop when Bus Fault exception occurs */
    while (1);
}

void UsageFault_Handler(void) {
        uart_printf("got fault!\n");
    /* Go to infinite loop when Usage Fault exception occurs */
    while (1);
}

#define SCB_VTOR (SCB+0x08)
#define RCC_CR      RCC
#define RCC_CFGR    (RCC + 0x04)
#define RCC_CIR     (RCC + 0x08)
#define SET_REG(addr,val) do { *(vu32*)(addr)=val; } while(0)
#define GET_REG(addr)     (*(vu32*)(addr))

void jumpDFU(u32 usrAddr) {

    SET_REG(RCC_CR, GET_REG(RCC_CR)     | 0x00000001);
    SET_REG(RCC_CFGR, GET_REG(RCC_CFGR) & 0xF8FF0000);
    SET_REG(RCC_CR, GET_REG(RCC_CR)     & 0xFEF6FFFF);
    SET_REG(RCC_CR, GET_REG(RCC_CR)     & 0xFFFBFFFF);
    SET_REG(RCC_CFGR, GET_REG(RCC_CFGR) & 0xFF80FFFF);

    SET_REG(RCC_CIR, 0x00000000);  /* disable all RCC interrupts */
    // Dedicated function with no call to any function (appart the last call)
    // This way, there is no manipulation of the stack here, ensuring that GGC
    // didn't insert any pop from the SP after having set the MSP.
    typedef void (*funcPtr)(void);
    u32 jumpAddr = *(vu32 *)(usrAddr+0x4); /* reset ptr in vector table */

    funcPtr usrMain = (funcPtr) jumpAddr;

    SET_REG(SCB_VTOR, (vu32) (usrAddr));

    asm volatile("msr msp, %0"::"g"
               (*(volatile u32 *)usrAddr));

    usrMain();                                /* go! */
}

void hard_fault_handler_c (unsigned int * hardfault_args)
{
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

  jumpDFU(0x08000000); // 
  while (1);
}

void panic() {
  DEBUG_PRINTLN("Panicking!!!\n");
  __asm("MOV r0, sp");
  __asm("BL hard_fault_handler_c");
  //DEBUG_PRINTLN("Panic reason; %s\n", reason);
  //DEBUG_PRINTLN("Panic caller; %s\n", caller);
  //DEBUG_PRINTLN("Line number; %i", lineNumber);
  while (1); // hang for panic, PROD devices should reset
}

struct u_id {
    uint16_t off0;
    uint16_t off2;
    uint32_t off4;
    uint32_t off8;
};

#define MMIO16(addr)  (*(volatile uint16_t *)(addr))
#define MMIO32(addr)  (*(volatile uint32_t *)(addr))
#define U_ID          0x1ffff7e8

/* Read U_ID register */
void uid_read(struct u_id *id)
{
    id->off0 = MMIO16(U_ID + 0x0);
    id->off2 = MMIO16(U_ID + 0x2);
    id->off4 = MMIO32(U_ID + 0x4);
    id->off8 = MMIO32(U_ID + 0x8);
}

int main(void) {
    uint8_t signing_test_key[32] = {0x6F, 0x3C, 0x89, 0x7F, 0xEA, 0xE1, 0x3A, 0x8A, 0x53, 0x4B, 0x83, 0xE2, 0x9B, 0xCE, 0x81, 0x79, 0x4A, 0x50, 0x98, 0x08, 0x4F, 0x4F, 0xF9, 0xF8, 0xB1, 0xB2, 0x8B, 0x0B, 0x82, 0x86, 0xEF, 0x97};
    uint8_t signing_test_pub[32] = {0xe5, 0x1e, 0x4e, 0x71, 0x5e, 0x37, 0xad, 0xea, 0x47, 0x81, 0x75, 0x6b, 0xb9, 0xc8, 0xae, 0xdc, 0x94, 0xc9, 0xa0, 0xf3, 0x6a, 0x79, 0x0b, 0x8b, 0x40, 0xa2, 0x7e, 0xd1, 0x9d, 0xdd, 0x46, 0x74};

    // Setup STM32 system (clock, PLL and Flash configuration)
    SystemInit();
    // Setup the GPIOs
    GPIO_Config();
    // Setup USART interface
    usart_init();

    // Continue boot process
    uart_printf("\r\nOS INIT\r\n");
    printVersionHeader();

    GPIOC->ODR ^= GPIO_Pin_13; // Turn boot status LED on

    // Test AES 
    if (!do_cbc_tests())
    {
        panic("AES CBC Enc/Dec test failed, hanging...", __FILE__, __LINE__);
    }
    DEBUG_PRINTLN("AES CBC Enc/Dec test passed.\n");

    // Get unique ID
    struct u_id id;
    uid_read(&id);

    DEBUG_PRINTLN("Unique ID: %X%X%X%X\n", id.off0, id.off2, id.off4, id.off8);

    // Get public key from unique id and then hash it
    uint8_t public[32];
    uint8_t secret[32];
    sha256_context ctx;
    unsigned char sha256sum[32];

    sha256_starts(&ctx);

    memset(secret, 0xFF, sizeof(secret));
    memcpy(secret, &id, sizeof(id));

    cf_curve25519_mul_base(public, secret);

    sha256_update(&ctx, secret, 32);
    sha256_finish(&ctx, sha256sum);

    DEBUG_PRINTLN("Secret key hash: ");
    print_hash(sha256sum);

    memset(sha256sum, 0xFF, sizeof(sha256sum));

    sha256_update(&ctx, public, 32);
    sha256_finish(&ctx, sha256sum);

    DEBUG_PRINTLN("Public key hash: ");
    print_hash(sha256sum);

    uart_printf("Waiting for host request...\n");
    //panic("DEBUG PANIC", __FILE__, __LINE__);
   // init_printf(NULL,putc_UART1);
   // printf("waddup tho\n");
    for(;;) {
        
    }
}

void Delay(volatile unsigned long delay) {
    for(; delay; --delay );
}

void GPIO_Config() {
    GPIO_InitTypeDef	GPIO_InitStructure;

    RCC_APB2PeriphClockCmd(RCC_APB2Periph_GPIOC, ENABLE);

    GPIO_InitStructure.GPIO_Pin = GPIO_Pin_13;
    GPIO_InitStructure.GPIO_Mode = GPIO_Mode_Out_PP;
    GPIO_InitStructure.GPIO_Speed = GPIO_Speed_50MHz;

    GPIO_Init(GPIOC, &GPIO_InitStructure);
}
