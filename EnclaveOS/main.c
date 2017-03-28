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
#include "stm32f10x_flash.h"
#include "printf_uart.h"
#include "aes.h"
#include "tests.h"
#include "curve25519.h"
#include "interrupts.h"
#include "sha256.h"
#include "div.h"
#include "mailbox.h"

void GPIO_Config();
void Delay(volatile unsigned long delay);
void MPU_SETUP(void);
void HAL_MPU_Enable(uint32_t MPU_Control);

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

#define RAM_ADDRESS_START                        (0x20000000UL)
#define RAM_SIZE                                 (0x19UL << 0UL)
#define PERIPH_ADDRESS_START                     (0x40000000)
#define PERIPH_SIZE                              (0x39UL << 0UL)
#define FLASH_ADDRESS_START                      (0x08000000)
#define FLASH_SIZE                               (0x27UL << 0UL)
#define portMPU_REGION_READ_WRITE                (0x03UL << MPU_RASR_AP_Pos)
#define portMPU_REGION_PRIVILEGED_READ_ONLY      (0x05UL << MPU_RASR_AP_Pos)
#define portMPU_REGION_READ_ONLY                 (0x06UL << MPU_RASR_AP_Pos)
#define portMPU_REGION_PRIVILEGED_READ_WRITE     (0x01UL << MPU_RASR_AP_Pos)
#define RAM_REGION_NUMBER                        (0x00UL << MPU_RNR_REGION_Pos)
#define FLASH_REGION_NUMBER                      (0x01UL << MPU_RNR_REGION_Pos)
#define PERIPH_REGION_NUMBER                     (0x02UL << MPU_RNR_REGION_Pos)
#define MPU_RASR_ENABLE_Pos                 0                                             /*!< MPU RASR: Region enable bit Position */
#define MPU_RASR_ENABLE_Msk                (1UL /*<< MPU_RASR_ENABLE_Pos*/)               /*!< MPU RASR: Region enable bit Disable Mask */

#define  MPU_ACCESS_SHAREABLE        ((uint8_t)0x01)
#define  MPU_ACCESS_NOT_SHAREABLE    ((uint8_t)0x00)
#define  MPU_HFNMI_PRIVDEF_NONE      ((uint32_t)0x00000000)
#define  MPU_HARDFAULT_NMI           ((uint32_t)0x00000002)
#define  MPU_PRIVILEGED_DEFAULT      ((uint32_t)0x00000004)
#define  MPU_HFNMI_PRIVDEF           ((uint32_t)0x00000006)

#define  MPU_REGION_NO_ACCESS        ((uint8_t)0x00)
#define  MPU_REGION_PRIV_RW          ((uint8_t)0x01)
#define  MPU_REGION_PRIV_RW_URO      ((uint8_t)0x02)
#define  MPU_REGION_FULL_ACCESS      ((uint8_t)0x03)
#define  MPU_REGION_PRIV_RO          ((uint8_t)0x05)
#define  MPU_REGION_PRIV_RO_URO      ((uint8_t)0x06)

#define  MPU_REGION_ENABLE     ((uint8_t)0x01)
#define  MPU_REGION_DISABLE    ((uint8_t)0x00)

#define  MPU_ACCESS_BUFFERABLE       ((uint8_t)0x01)
#define  MPU_ACCESS_NOT_BUFFERABLE   ((uint8_t)0x00)

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

typedef void (*failpls)(void);
void cause_hard_fault(void) {
  failpls usrMain = (failpls) NULL;
  usrMain(); /* will cause a hard fault, as the function pointer is NULL */
}

int main(void) {
    // Setup STM32 system (clock, PLL and Flash configuration)
    SystemInit();
    // Setup the GPIOs
    GPIO_Config();
    // Setup USART interface
    usart_init();
    __enable_fault_irq();
    __enable_irq(); 

    FLASH_Status status = FLASH_EnableWriteProtection(FLASH_WRProt_AllPages);
    if (status != FLASH_COMPLETE)
    {
      debug_print("Couldn't lock writing flash\n");
    }

    MPU_SETUP();
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

    //panic("DEBUG PANIC", __FILE__, __LINE__);
    // init_printf(NULL,putc_UART1);
    // printf("waddup tho\n");
    while (1) {

    }
}

typedef struct
{
  uint8_t                Enable;                /*!< Specifies the status of the region. 
                                                     This parameter can be a value of @ref CORTEX_MPU_Region_Enable                 */
  uint8_t                Number;                /*!< Specifies the number of the region to protect. 
                                                     This parameter can be a value of @ref CORTEX_MPU_Region_Number                 */
  uint32_t               BaseAddress;           /*!< Specifies the base address of the region to protect.                           */
  uint8_t                Size;                  /*!< Specifies the size of the region to protect. 
                                                     This parameter can be a value of @ref CORTEX_MPU_Region_Size                   */
  uint8_t                SubRegionDisable;      /*!< Specifies the number of the subregion protection to disable. 
                                                     This parameter must be a number between Min_Data = 0x00 and Max_Data = 0xFF    */
  uint8_t                TypeExtField;          /*!< Specifies the TEX field level.
                                                     This parameter can be a value of @ref CORTEX_MPU_TEX_Levels                    */
  uint8_t                AccessPermission;      /*!< Specifies the region access permission type. 
                                                     This parameter can be a value of @ref CORTEX_MPU_Region_Permission_Attributes  */
  uint8_t                DisableExec;           /*!< Specifies the instruction access status. 
                                                     This parameter can be a value of @ref CORTEX_MPU_Instruction_Access            */
  uint8_t                IsShareable;           /*!< Specifies the shareability status of the protected region. 
                                                     This parameter can be a value of @ref CORTEX_MPU_Access_Shareable              */
  uint8_t                IsCacheable;           /*!< Specifies the cacheable status of the region protected. 
                                                     This parameter can be a value of @ref CORTEX_MPU_Access_Cacheable              */
  uint8_t                IsBufferable;          /*!< Specifies the bufferable status of the protected region. 
                                                     This parameter can be a value of @ref CORTEX_MPU_Access_Bufferable             */
}MPU_Region_InitTypeDef;


void HAL_MPU_Disable(void)
{
  /* Disable fault exceptions */
  SCB->SHCSR &= ~SCB_SHCSR_MEMFAULTENA_Msk;
  
  /* Disable the MPU */
  MPU->CTRL  &= ~MPU_CTRL_ENABLE_Msk;
}

void HAL_MPU_Enable(uint32_t MPU_Control)
{
  /* Enable the MPU */
  MPU->CTRL   = MPU_Control | MPU_CTRL_ENABLE_Msk;
  
  /* Enable fault exceptions */
  SCB->SHCSR |= SCB_SHCSR_MEMFAULTENA_Msk;
}

void HAL_MPU_ConfigRegion(MPU_Region_InitTypeDef *MPU_Init)
{
  /* Check the parameters */
  assert_param(IS_MPU_REGION_NUMBER(MPU_Init->Number));
  assert_param(IS_MPU_REGION_ENABLE(MPU_Init->Enable));

  /* Set the Region number */
  MPU->RNR = MPU_Init->Number;


  /* Check the parameters */
  assert_param(IS_MPU_INSTRUCTION_ACCESS(MPU_Init->DisableExec));
  assert_param(IS_MPU_REGION_PERMISSION_ATTRIBUTE(MPU_Init->AccessPermission));
  assert_param(IS_MPU_TEX_LEVEL(MPU_Init->TypeExtField));
  assert_param(IS_MPU_ACCESS_SHAREABLE(MPU_Init->IsShareable));
  assert_param(IS_MPU_ACCESS_CACHEABLE(MPU_Init->IsCacheable));
  assert_param(IS_MPU_ACCESS_BUFFERABLE(MPU_Init->IsBufferable));
  assert_param(IS_MPU_SUB_REGION_DISABLE(MPU_Init->SubRegionDisable));
  assert_param(IS_MPU_REGION_SIZE(MPU_Init->Size));
  
  MPU->RBAR = MPU_Init->BaseAddress;
  MPU->RASR = ((uint32_t)MPU_Init->DisableExec             << MPU_RASR_XN_Pos)   |
              ((uint32_t)MPU_Init->AccessPermission        << MPU_RASR_AP_Pos)   |
              ((uint32_t)MPU_Init->TypeExtField            << MPU_RASR_TEX_Pos)  |
              ((uint32_t)MPU_Init->IsShareable             << MPU_RASR_S_Pos)    |
              ((uint32_t)MPU_Init->IsCacheable             << MPU_RASR_C_Pos)    |
              ((uint32_t)MPU_Init->IsBufferable            << MPU_RASR_B_Pos)    |
              ((uint32_t)MPU_Init->SubRegionDisable        << MPU_RASR_SRD_Pos)  |
              ((uint32_t)MPU_Init->Size                    << MPU_RASR_SIZE_Pos) |
              ((uint32_t)MPU_Init->Enable                  << MPU_RASR_ENABLE_Pos);

}

/**
  * @brief  Configures the main MPU regions.
  * @param  None
  * @retval None
  */
#define REGION_Enabled  (0x01)
#define REGION_32K      (14 << 1)      // 2**15 == 32k
#define NORMAL          (8 << 16)      // TEX:0b001 S:0b0 C:0b0 B:0b0
void MPU_SETUP(void)
{
  /* Disable MPU */
  MPU->CTRL = 0;
  
  MPU->RBAR = 0x00000000 | 0x10 | 0;
  MPU->RASR = REGION_Enabled | NORMAL | REGION_32K | MPU_REGION_PRIV_RO;
  
  MPU->CTRL = 1;
  __ISB();
  __DSB();
  /*
  MPU_Region_InitTypeDef MPU_InitStruct;
  HAL_MPU_Disable();

  MPU_InitStruct.Enable = MPU_REGION_DISABLE;
  MPU_InitStruct.BaseAddress = FLASH_ADDRESS_START; // 0x080000000
  MPU_InitStruct.Size = FLASH_SIZE;
  MPU_InitStruct.IsBufferable = MPU_ACCESS_NOT_BUFFERABLE;
  MPU_InitStruct.Number = FLASH_REGION_NUMBER;
  MPU_InitStruct.AccessPermission = MPU_REGION_NO_ACCESS;
  MPU_InitStruct.SubRegionDisable = 0x30;
  HAL_MPU_ConfigRegion(&MPU_InitStruct);

  SCB->AFSR |= 2; 

  HAL_MPU_Enable(MPU_PRIVILEGED_DEFAULT);
  */
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



/**
  * @brief  Reports the name of the source file and the source line number
  *         where the assert_param error has occurred.
  * @param  file: pointer to the source file name
  * @param  line: assert_param error line source number
  * @retval None
  */
void assert_failed(uint8_t* file, uint32_t line)
{ 
  /* User can add his own implementation to report the file name and line number,
     ex: printf("Wrong parameters value: file %s on line %d\r\n", file, line) */

  /* Infinite loop */
  while (1)
  {
  }
}
