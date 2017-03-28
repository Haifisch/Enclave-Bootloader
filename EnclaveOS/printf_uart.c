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

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <limits.h>
#include <unistd.h>
#include <errno.h>
#include <stdarg.h>

#include "printf_uart.h"

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

void hexdump(unsigned char *data, size_t size)
{
    int i;
    char cs[17];
    memset(cs, 0, 17);

    for(i = 0; i < size; i++)
    {
        if(i != 0 && i % 0x10 == 0)
        {
            debug_print(" |%s|\n", cs);
            memset(cs, 0, 17);
        }
        else if(i != 0 && i % 0x8 == 0)
        {
            debug_print(" ",0);
        }
        debug_print("%02X ", data[i]);
        cs[(i % 0x10)] = (data[i] >= 0x20 && data[i] <= 0x7e) ? data[i] : '.';
    }

    i = i % 0x10;
    if(i != 0)
    {
        if(i <= 0x8)
        {
            debug_print(" ",0);
        }
        while(i++ < 0x10)
        {
            debug_print("   ",0);
        }
    }
    debug_print(" |%s|\n", cs);
}

void print_hash(unsigned char hash[])
{
   int idx;
   for (idx=0; idx < 32; idx++)
      uart_printf("%02x",hash[idx]);
   uart_printf("\n");
}


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
