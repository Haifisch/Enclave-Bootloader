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
       0xbd, 0x0c, 0x2d, 0x04, 0x2e, 0x5a, 0x95, 0xc6, 0xb6, 0x28, 0xfc, 0x3f, 0x85, 0x6c, 0xa1, 0xfb, 0xb5, 0x25, 0x07, 0x38, 0xc0, 0x05, 0x9d, 0x44, 0x04, 0xa7, 0xe3, 0xa6, 0xac, 0x3b, 0xb8, 0x41
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
    unsigned char uniqueID[0x17];
    if (!QEMU_BUILD)
    {
    	struct u_id id;
	    uid_read(&id);
	    sprintf(uniqueID,"%X%X%X%X", id.off0, id.off2, id.off4, id.off8);
	    sha256_update(&ctx, uniqueID, 0x17);
    }

    //debug_print("%s\n", uniqueID);
    
    sha256_finish(&ctx, sha256sum);
    print_hash(sha256sum);
    // verify signature against recalc hash
    uint8_t sigbuff[0x40];
    memcpy(sigbuff, (uint8_t*)(hdr->signing.imageSignature), 0x40);

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
