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

#include "hardware.h"
#include "sha256.h"
#include "edsign.h"
#include "image.h"

uint8_t rootCA[32] = {
      0x0f, 0x72, 0xeb, 0xd1, 0x64, 0x3e, 0xab, 0x54, 0xc8, 0xcf, 0x60, 0xe6, 0x6f, 0xc3, 0x9d, 0x64, 0xa4, 0xcf, 0x43, 0x77, 0x46, 0x7b, 0x09, 0x52, 0x19, 0xc7, 0x06, 0x6c, 0x72, 0x1d, 0x3c, 0x86
    };

static void print_hex(const char *label, const uint8_t *data, int len)
{
    int i;

    uart_printf("%s: ", label);
    for (i = 0; i < len; i++)
        uart_printf("%02x", data[i]);
    uart_printf("\n");
}

void failErase () {
	// for whatever reason this only flashes upto 0x08008800
	flashErasePage((u32)(0x08008000));
	flashErasePage((u32)(0x08008000+1024));
	flashErasePage((u32)(0x08008000+(u32)(0x190*2)));
	flashErasePage((u32)(0x08008000+(u32)(0x190*3)));
	flashErasePage((u32)(0x08008000+(u32)(0x190*4)));
	flashErasePage((u32)(0x08008000+(u32)(0x190*5)));
}

int imageCheckFromAddress(ImageObjectHandle *newHandle, vu32 flashAddress, bool shouldEraseFlashOnFail)
{
	ImageRootHeader		*hdr;
	ImageInternalState		state;
	int bufferSize = 0x28+0x40;
	unsigned char imageBuffer[bufferSize];
    memset(imageBuffer, 0xFF, sizeof(imageBuffer));
    memcpy(imageBuffer, (vu32 *)flashAddress, bufferSize);
    memset(&state, 0, sizeof(state));

	hdr = (ImageRootHeader *)imageBuffer;
	if (bufferSize < sizeof(hdr)) {
		debug_print("buffer size %X too small for header size %X\n", bufferSize, sizeof(*hdr));
		if (shouldEraseFlashOnFail)
		{
			failErase();
		}
		return(EINVAL);		/* buffer too small to really contain header */
	}
	if ((hdr->header.magic) != kImageHeaderMagic) {
		debug_print("bad magic 0x%08x expecting 0x%08x\n", (hdr->header.magic), kImageHeaderMagic);
		state.flags = kImageImageMissingMagic;
		if (shouldEraseFlashOnFail)
		{
			failErase();
		}
		*newHandle = &state;
		return(kImageImageMissingMagic);		/* magic must match */
	}
	if ((hdr->signing.imageType) != 0x45444f53)
	{
		debug_print("bad magic 0x%08x expecting 0x%X\n", (hdr->signing.imageType), 0x45444f53);
		state.flags = kImageImageMissingMagic;
		if (shouldEraseFlashOnFail)
		{
			failErase();
		}
		*newHandle = &state;
		return(kImageImageMissingMagic);		/* magic must match */
	}
	state.flags = kImageImageWasInstantiated;

	debug_print("dataSize: 0x%X\n", (hdr->header.dataSize));

	state.cursor = hdr->header.dataSize;
	state.lastTag = -1;

	unsigned char sha256sum[32];

    memset(sha256sum, 0xFF, sizeof(sha256sum));

    sha256_context ctx;
    sha256_starts(&ctx);

    int buffSize = 0x1;
    char buff[buffSize];

    int i = 0x84;
    hexdump((flashAddress+i), 0x10);

    int finish = hdr->header.dataSize + 0x84;
    debug_print("Start: %X\nFinish: %X\n", (flashAddress+i), (flashAddress+ finish));
    while (i < finish)
    {
    	memset(buff, 0xFF, buffSize);
    	memcpy(buff, (unsigned char *)(flashAddress+i), buffSize);
		sha256_update(&ctx, (vu32 *)(flashAddress+i), buffSize);
		i += 0x1;
    }
    debug_print("Ended at: %X\n", (flashAddress+i));
    hexdump((vu32 *)(flashAddress+i), 0x10);
    if ((flashAddress+i) != (flashAddress+finish))
    {
    	debug_print("Calculated hash is probably wrong...\n");
    	state.flags = kImageImageHashCalcFailed;
    	*newHandle = &state;
		return(kImageImageHashCalcFailed);
    }

    if (!QEMU_BUILD)
    {
    	struct u_id id;
		unsigned char uniqueID[0x17];
		unsigned char temp_sha256sum[32];  
		uint8_t publickey[EDSIGN_PUBLIC_KEY_SIZE];
		// read our unique id
		uid_read(&id);
		sprintf(uniqueID,"%X%X%X%X", id.off0, id.off2, id.off4, id.off8);
		// start sha256 context
		sha256_context ctx2;
		sha256_starts(&ctx2);
		// hash in our unique id
		sha256_update(&ctx2, uniqueID, 0x17);
		sha256_finish(&ctx2, temp_sha256sum);
		// get our public key
		memset(publickey, 0, EDSIGN_PUBLIC_KEY_SIZE);
		edsign_sec_to_pub(publickey, temp_sha256sum);
		debug_print("publickey:\n");
		hexdump(publickey, 32);
    	/*
    	struct u_id id;
	    uid_read(&id);
	    sprintf(uniqueID,"%X%X%X%X", id.off0, id.off2, id.off4, id.off8);
	    */
	    sha256_update(&ctx, (unsigned char*)publickey, 32);
    }

    //debug_print("%s\n", uniqueID);
    
    sha256_finish(&ctx, sha256sum);
    // verify signature against recalc hash
    debug_print("Signature:\n");
    hexdump(hdr->signing.imageSignature, 0x40);
	debug_print("sha256sum:\n");
	print_hash(sha256sum);

	char sigbuff[64];
	memcpy(sigbuff, hdr->signing.imageSignature, 64);

    if (edsign_verify(sigbuff, rootCA, sha256sum, 32) <= 0) {
    	state.flags = kImageImageRejectSignature;
    	if (shouldEraseFlashOnFail)
		{
			failErase();
		}
    	*newHandle = &state;
    	return kImageImageRejectSignature;
    } else {
    	state.flags = kImageImageIsTrusted;
    	*newHandle = &state;
    	return kImageImageIsTrusted;
    }
	*newHandle = &state;
	return(0);
}
