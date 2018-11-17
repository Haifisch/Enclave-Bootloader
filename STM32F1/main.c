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

extern char   __BUILD_DATE;
extern char   __BUILD_NUMBER;

/*
  Print the device's public key + signature (ed25519 between the device and the root ca)
  the device is probably in DFU when this is needed -- the restore tool should use this to request a signed firmware from the signing server.
*/
void transmit_publickey_data() 
{
    struct u_id id;
    unsigned char uniqueID[0x17]; // device unique id
    uint8 enclaveID[32]; // sha2'd unique id
    char signature[EDSIGN_SIGNATURE_SIZE]; // signature of our enclave id
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
    // store the hash as our enclave id
    sha256_finish(&ctx, enclaveID);
    // zero out public key memory
    memset(publickey, 0, EDSIGN_PUBLIC_KEY_SIZE);
    // get ed25519 public key from our enclave id
    edsign_sec_to_pub((unsigned char*)publickey, enclaveID); // secret --> enclave id ===> 25519 public key
    #if DEBUG
        print_hex("Enclave ID", enclaveID, sizeof(enclaveID));
    #endif
    // encode the ed25519 public key for transport
    encode_b64(publickey, base64_pub, 0x20);
    // zero out signature memory 
    memset(signature, 0, EDSIGN_SIGNATURE_SIZE);
    // sign the public key for our rootCA 
    edsign_sign((uint8_t*)signature, rootCA, enclaveID, (uint8_t*)publickey, EDSIGN_PUBLIC_KEY_SIZE);
    // encode signature for transport
    encode_b64(signature, base64_signature, 0x64);

    // spit the base64 publickey
    debug_print("\n\n[BEGIN_PUB_DATA]\n");
    debug_print("%s", base64_pub);
    debug_print("[END_PUB_DATA]\n");
    // sput the base64 signature
    debug_print("\n[BEGIN_SIGNATURE_DATA]\n");
    debug_print("%s", base64_signature);
    debug_print("[END_SIGNATURE_DATA]\n");
}

/*
    Printable boot header
*/
void print_bootheader() 
{
    uart_printf("[--------------------------------------------]\n");
    char* letter[6]; 
    letter[0] = "   ______            _                 \n";
    letter[1] = "  |  ____|          | |                \n";
    letter[2] = "  | |__   _ __   ___| | __ ___   _____ \n";
    letter[3] = "  |  __| | '_ \\ / __| |/ _` \\ \\ / / _ \\\n";
    letter[4] = "  | |____| | | | (__| | (_| |\\ V /  __/\n";
    letter[5] = "  |______|_| |_|\\___|_|\\__,_| \\_/ \\___|\n\n";
    for (int i = 0; i < 6; ++i) { uart_printf(letter[i]); } // print out
    debug_print("  %s %s\n", __DATE__, __TIME__);
    debug_print("  DEVID %08X\n", *((uint32_t *)0x1E0032000)); // 0xE0042000 + 0xFFFF0000
    debug_print("  VER: 0x%X REV: 0x%X\n", __BUILD_NUMBER, 0x15);
    debug_print("  Security Fusing ::: %s\n", isSecure() ? "Secure":"Insecure");
    debug_print("  Production Fusing ::: %s\n", isProduction() ? "Production":"Development");
    uart_printf("[--------------------------------------------]\n");
}


/*
    Bootloader main
*/
int main() 
{
    // default state is true, logically if all else fails we should fallback into DFU and not jump into userland
    bool refuse_user_jump = TRUE; 

    // low level hardware init  
    systemReset(); // peripherals but not PC
    setupCLK();
    setupLEDAndButton();
    setupFLASH();
    uartInit();
    setupUSB();

    // Init!
    uart_printf("\033[2J\n");
    uart_printf("Bootloader init!\n\n");
    print_bootheader();
    strobePin(LED_BANK, LED_PIN, 5, BLINK_FAST,LED_ON_STATE); // show that we're alive via LED 

    // Read DFU pin state 
    if (readPin(GPIOB, 15) == 0x0) // force dfu
    {
        refuse_user_jump = TRUE;
    } 

    // verify boot chain
    debug_print("checking chain...\n");
    // setup image structure 
    ImageObjectHandle imageHandle;
    // validate flash     
    switch (imageCheckFromAddress(&imageHandle, USER_CODE_FLASH0X8008000, 0)) // if anything fails to verify we need to kick ourselves into the DFU loop
    {
        case kImageImageIsTrusted:
            debug_print("Boot OK\n");
            refuse_user_jump = FALSE;
            break;

        case kImageImageMissingMagic:
            transmit_publickey_data();
            debug_print("\nFirmware missing... waiting in DFU\n");
            refuse_user_jump = TRUE;
            break;

        case kImageImageRejectSignature:
            debug_print("\nSignature validation failed... waiting in DFU\n");
            refuse_user_jump = TRUE;
            break;

        case kImageImageHashCalcFailed:
            debug_print("\nHash calculation failed... waiting in DFU\n");
            refuse_user_jump = TRUE;
            break;
            
        default:
            debug_print("\n!!! FATAL !!!\n");
            refuse_user_jump = TRUE;
            break;
    }

    while (refuse_user_jump) // DFU spinlock
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
    if (refuse_user_jump == FALSE)
    {
        debug_print("Jumping to OS.\n");
        jumpToUser((USER_CODE_FLASH0X8008000+0x84));    
    }
    
    return 0; // Added to please the compiler
}