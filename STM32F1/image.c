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

static void print_hex(const char *label, const uint8_t *data, int len)
{
    int i;

    uart_printf("%s: ", label);
    for (i = 0; i < len; i++)
        uart_printf("%02x", data[i]);
    uart_printf("\n");
}


int imageCheckFromAddress(ImageObjectHandle *newHandle, uint32_t flashAddress, bool shouldEraseFlashOnFail)
{
	ImageObjectHeader		*hdr;
	ImageInternalState		state;
	int bufferSize = 0x28+0x40;
	unsigned char imageBuffer[bufferSize];
    memset(imageBuffer, 0xFF, sizeof(imageBuffer));
    memcpy(imageBuffer, (vu32 *)flashAddress, bufferSize);
    flashUnlock();
    memset(&state, 0, sizeof(state));

	hdr = (ImageObjectHeader *)imageBuffer;
	u32 flashCnt = 0x0;

	if (bufferSize < sizeof(hdr)) {
		uart_printf("buffer size %X too small for header size %X\n", bufferSize, sizeof(*hdr));
		if (shouldEraseFlashOnFail)
		{
			flashCnt = 0x0;
			while ((flashAddress+flashCnt) <= ((hdr->ihBufferLength)+0x10)) {
				flashErasePage((u32)(0x08008000+flashCnt));
				flashCnt += 0x3F0;
			}
		}
		return(EINVAL);		/* buffer too small to really contain header */
	}
	if ((hdr->ihMagic) != kImageHeaderMagic) {
		uart_printf("bad magic 0x%08x expecting 0x%08x\n", (hdr->ihMagic), kImageHeaderMagic);
		state.flags = kImageImageMissingMagic;
		if (shouldEraseFlashOnFail)
		{
			flashCnt = 0x0;
			while ((flashAddress+flashCnt) <= ((hdr->ihBufferLength)+0x10)) {
				flashErasePage((u32)(0x08008000+flashCnt));
				flashCnt += 0x3F0;
			}
		}
		
		*newHandle = &state;
		return(kImageImageMissingMagic);		/* magic must match */
	}

	state.flags = kImageImageWasInstantiated;

	state.cursor = (hdr->ihBufferLength)+0x10;
	state.lastTag = -1;

	unsigned char sha256sum[32];

    memset(sha256sum, 0xFF, sizeof(sha256sum));

    sha256_context ctx;
    sha256_starts(&ctx);
    char buff[0x4];

    int i = 0x84;

    while ((flashAddress+i) <= (flashAddress+state.cursor))
    {
      memset(buff, 0xFF, 0x4);
      memcpy(buff, (char *)(flashAddress+i), 0x4);
      sha256_update(&ctx, (vu32 *)(flashAddress+i), 0x4);
      i += 0x4;
    }

    // hash in our unique ID
    struct u_id id;
    uid_read(&id);
    unsigned char uniqueID[23];
    sprintf(uniqueID,"%X%X%X%X", id.off0, id.off2, id.off4, id.off8);
    sha256_update(&ctx, uniqueID, 23);
    sha256_finish(&ctx, sha256sum);

 	uint8_t rootCA[32] = {
       0xbd, 0x0c, 0x2d, 0x04, 0x2e, 0x5a, 0x95, 0xc6, 0xb6, 0x28, 0xfc, 0x3f, 0x85, 0x6c, 0xa1, 0xfb, 0xb5, 0x25, 0x07, 0x38, 0xc0, 0x05, 0x9d, 0x44, 0x04, 0xa7, 0xe3, 0xa6, 0xac, 0x3b, 0xb8, 0x41
    };
    // verify signature against recalc hash

    uint8_t sigbuff[0x40];
    memcpy(sigbuff, (uint8_t*)(hdr->ihBuffer), 0x40);

    if (edsign_verify(sigbuff, rootCA, sha256sum, 32) <= 0) {
    	state.flags = kImageImageRejectSignature;
    	if (shouldEraseFlashOnFail)
		{
			flashCnt = 0x0;
			while ((flashAddress+flashCnt) <= ((hdr->ihBufferLength)+0x10)) {
				flashErasePage((u32)(0x08008000+flashCnt));
				flashCnt += 0x3F0;
			}
			uart_printf("finished: %X\n", flashCnt);
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
