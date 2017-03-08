/* *****************************************************************************
 * The MIT License
 *
 * Copyright (c) 2010 LeafLabs LLC.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 * ****************************************************************************/

/**
 *  @file main.c
 *
 *  @brief main loop and calling any hardware init stuff. timing hacks for EEPROM
 *  writes not to block usb interrupts. logic to handle 2 second timeout then
 *  jump to user code.
 *
 */
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <limits.h>
#include <unistd.h>
#include <errno.h>
#include <stdarg.h>

#include "common.h"
#include "dfu.h"
#include "image.h"
#include "sha256.h"

#define PERIPH_BASE           ((uint32_t)0x40000000) /*!< Peripheral base address in the alias region */

#define PERIPH_BB_BASE        ((uint32_t)0x42000000) /*!< Peripheral base address in the bit-band region */

#define FSMC_R_BASE           ((uint32_t)0xA0000000) /*!< FSMC registers base address */

/*!< Peripheral memory map */
#define APB1PERIPH_BASE       PERIPH_BASE
#define APB2PERIPH_BASE       (PERIPH_BASE + 0x10000)

#define USART1_BASE           (APB2PERIPH_BASE + 0x3800)
#define USART1              ((USART_TypeDef *) USART1_BASE)

extern volatile dfuUploadTypes_t userUploadType;

void print_hash(unsigned char hash[])
{
   int idx;
   for (idx=0; idx < 32; idx++)
      uart_printf("%02x",hash[idx]);
   uart_printf("\n");
}

int main() 
{
	bool no_user_jump = FALSE;
	bool dont_wait=FALSE;
	
    systemReset(); // peripherals but not PC
    setupCLK();
    setupLEDAndButton();
    setupUSB();
    setupFLASH();
    uartInit();
    usbReset();
	uart_printf("\nBootloader init...\n");

    if (readPin(GPIOB, 15) == 0x0)
	{
		no_user_jump = TRUE;
	} 

	uart_printf("checking chain...\n");
	ImageObjectHandle imageHandle;

    int ret = imageCheckFromAddress(&imageHandle, USER_CODE_FLASH0X8008000, 0);
    
    uart_printf("image check ret: %X\n", ret);
	switch (ret)
	{
		case kImageImageIsTrusted:
			uart_printf("Boot OK\n");
			no_user_jump = FALSE;
			break;

		case kImageImageMissingMagic:
			uart_printf("Firmware missing... waiting in DFU\n");
			no_user_jump = TRUE;
			break;

		case kImageImageRejectSignature:
			uart_printf("Signature unverified... waiting in DFU\n");
			no_user_jump = TRUE;
			break;

		default:
			break;
	}
	strobePin(LED_BANK, LED_PIN, 5, BLINK_FAST,LED_ON_STATE);

	int delay_count = 0;
	while ((delay_count++ < BOOTLOADER_WAIT) || no_user_jump)
	{

		strobePin(LED_BANK, LED_PIN, 1, BLINK_SLOW,LED_ON_STATE);

		if (dfuUploadStarted()) 
		{
			uart_printf("DFU finished upload\n");
			dfuFinishUpload(); // systemHardReset from DFU once done
		}
	}

	if (no_user_jump == FALSE)
	{
		uart_printf("Jumping to OS.\n");
		jumpToUser((USER_CODE_FLASH0X8008000+0x84));	
	}
	
	return 0;// Added to please the compiler
}