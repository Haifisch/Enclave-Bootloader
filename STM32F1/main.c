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
#include "cencode.h"
#include "cdecode.h"
/*
	Base64 functions
*/
size_t decode_b64(const char* input, char* output)
{
    base64_decodestate s;
    size_t cnt;

    base64_init_decodestate(&s);
    cnt = base64_decode_block(input, strlen(input), output, &s);
    output[cnt] = 0;

    return cnt;
}

size_t encode_b64(const char* input, char* output)
{
    base64_encodestate s;
    size_t cnt;

    base64_init_encodestate(&s);
    cnt = base64_encode_block(input, strlen(input), output, &s);
    cnt += base64_encode_blockend(output + cnt, &s);
    output[cnt] = 0;

    return cnt;
}

/*
  Print the device's public key + signature (ed25519 between the device and the root ca)
  the device is probably in DFU when this is needed -- the restore tool should use this to request a signed firmware from the signing server.
*/
void transmit_publickey_data() {
  struct u_id id;
  unsigned char uniqueID[0x17];
  unsigned char sha256sum[32];  
  char signature[EDSIGN_SIGNATURE_SIZE];
  char publickey[EDSIGN_PUBLIC_KEY_SIZE];
  char base64_pub[256];
  char base64_signature[256];

  // read our unique id
  uid_read(&id);
  sprintf(uniqueID,"%X%X%X%X", id.off0, id.off2, id.off4, id.off8);
  // start sha256 context
  sha256_context ctx;
  sha256_starts(&ctx);
  // hash in our unique id
  sha256_update(&ctx, uniqueID, 0x17);
  sha256_finish(&ctx, sha256sum);
  // get our public key
  edsign_sec_to_pub((uint8_t*)publickey, sha256sum);
  encode_b64(publickey, base64_pub);

  memset(signature, 0, EDSIGN_SIGNATURE_SIZE);
  // sign the pub
  edsign_sign((uint8_t*)signature, rootCA, sha256sum, (uint8_t*)publickey, EDSIGN_PUBLIC_KEY_SIZE);
  
  encode_b64(signature, base64_signature);

  debug_print("[BEGIN_PUB_DATA][BEGIN_PUB]%s[END_PUB][END_PUB_DATA]", base64_pub);
  debug_print("[BEGIN_SIGNATURE_DATA][BEGIN_SIGNATURE]%s[END_SIGNATURE][END_SIGNATURE_DATA]", base64_signature);
}

/*
	Bootloader main
*/
int main() 
{
	bool no_user_jump = FALSE;

	// low level hardware init	
    systemReset(); // peripherals but not PC
    setupCLK();
    setupLEDAndButton();
    setupFLASH();
    uartInit();
	setupUSB();

	uart_printf("\nBootloader init...\n");
    if (readPin(GPIOB, 15) == 0x0) // force dfu
	{
		no_user_jump = TRUE;
	} 

	// verify chain
	debug_print("checking chain...\n");
	ImageObjectHandle imageHandle;
    int ret = imageCheckFromAddress(&imageHandle, USER_CODE_FLASH0X8008000, 0);
    debug_print("image check ret: %X\n", ret);
	switch (ret) // if anything fails to verify we need to kick ourselves into the DFU loop
	{
		case kImageImageIsTrusted:
			debug_print("Boot OK\n");
			no_user_jump = FALSE;
			break;

		case kImageImageMissingMagic:
			transmit_publickey_data();
			debug_print("\nFirmware missing... waiting in DFU\n");
			no_user_jump = TRUE;
			break;

		case kImageImageRejectSignature:
			debug_print("\nSignature unverified... waiting in DFU\n");
			no_user_jump = TRUE;
			break;

		case kImageImageHashCalcFailed:
			debug_print("\nHash calculation failed... waiting in DFU\n");
			no_user_jump = TRUE;
			break;
			
		default:
			break;
	}

	strobePin(LED_BANK, LED_PIN, 5, BLINK_FAST,LED_ON_STATE);
	while (no_user_jump)
	{
		// we're spinning in DFU waiting for an upload...
		strobePin(LED_BANK, LED_PIN, 1, BLINK_SLOW,LED_ON_STATE);
		if (dfuUploadStarted()) 
		{
			debug_print("DFU finished upload\n");
			dfuFinishUpload(); // systemHardReset from DFU once done
		}
	}

	// we have the OS verified so lets jump to it. 
	if (no_user_jump == FALSE)
	{
		debug_print("Jumping to OS.\n");
		jumpToUser((USER_CODE_FLASH0X8008000+0x84));	
	}
	
	return 0;// Added to please the compiler
}