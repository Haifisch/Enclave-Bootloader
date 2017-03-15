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
#include "printf_uart.h"
#include "aes.h"
#include "tests.h"
#include "curve25519.h"
#include "interrupts.h"
#include "sha256.h"
#include "div.h"
#include "mailbox.h"

void GPIO_Config();

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
    // Setup STM32 system (clock, PLL and Flash configuration)
    SystemInit();
    // Setup the GPIOs
    GPIO_Config();
    // Setup USART interface
    usart_init();

    // Continue boot process
    uart_printf("\n\nOS INIT\n");
    printVersionHeader();

    mailboxTestSend();

    GPIOC->ODR ^= GPIO_Pin_13; // Turn boot status LED on

    // Test AES 
    if (!do_cbc_tests())
    {
        panic("AES CBC Enc/Dec test failed, hanging...", __FILE__, __LINE__);
    }
    debug_print("AES CBC Enc/Dec test passed.\n");

    // Get unique ID
    struct u_id id;
    uid_read(&id);

    debug_print("ECID: %X%X%X%X\n", id.off0, id.off2, id.off4, id.off8);

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

    debug_print("Secret key hash: ");
    print_hash(sha256sum);

    memset(sha256sum, 0xFF, sizeof(sha256sum));

    sha256_update(&ctx, public, 32);
    sha256_finish(&ctx, sha256sum);

    debug_print("Public key hash: ");
    print_hash(sha256sum);

    uart_printf("Waiting for host request...\n");

    int a = 10;
    int b = 0;
    int c;
    c = div(a, b);

    uart_printf("we shouldn't be here\n");
    //panic("DEBUG PANIC", __FILE__, __LINE__);
    // init_printf(NULL,putc_UART1);
    // printf("waddup tho\n");
    for( ;; )
    {

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

