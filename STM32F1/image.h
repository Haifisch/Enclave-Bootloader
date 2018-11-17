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
#include <stdint.h>

#ifndef __IMAGE_H
#define __IMAGE_H

typedef struct _ImageObjectHeader {
	uint32_t	ihMagic;
#define kImageHeaderMagic		'Ebc2'
	uint32_t	ihSkipDistance;
	uint32_t	ihBufferLength;

	uint32_t	ihSignedLength;
	uint32_t	ihType;
	uint8_t	ihBuffer[];
} ImageObjectHeader;

typedef struct _ImageInternalState {
	ImageObjectHeader		*image;
	uint32_t			flags;
# define kImageImageWasInstantiated	0x1
# define kImageImageRejectSignature 0x2
# define kImageImageIsTrusted		0x3	
# define kImageImageMissingMagic 	0x4
# define kImageImageHashCalcFailed  0x5
	size_t				allocSize;

	int				cursor;
	int				lastTag;
} ImageInternalState;

struct _ImageInternalState;
typedef struct _ImageInternalState	*ImageObjectHandle;

typedef enum {
    IMAGE_PROD_DEVELOPMENT = 0,
    IMAGE_PROD_PRODUCTION = 1,
} ImageProductionType;

#define kImageMagic             'Ebc2'

/* Image3 Tags */
#define kImageTagData               'DATA'
#define kImageTagType               'TYPE'
#define kImageTagSignature          'EDSN'
#define kImageTagECID               'ECID'
#define kImageTagVersion       		'VERS'      
#define kImageTagProduct            'PROD'

typedef struct ImageHeader {
    uint32_t magic;
    uint32_t size;
    uint32_t dataSize;
    uint32_t imageType;
} __attribute__ ((packed)) ImageHeader;

typedef struct ImageSigningExtension {
    uint32_t imageType;
    uint8_t  imageSignature[EDSIGN_SIGNATURE_SIZE];
} __attribute__ ((packed)) ImageSigningExtension;


typedef struct ImageRootHeader {
    ImageHeader header;
    ImageSigningExtension signing;
} __attribute__ ((packed)) ImageRootHeader;

/*
typedef struct Image3Keybag {
    uint32_t state;
    uint32_t type;
    uint8_t iv[16];
    uint8_t key[32];
} __attribute__ ((packed)) Image3Keybag;
*/
typedef struct __ImageStruct {
    ImageRootHeader        *rootHeader;
    void*                   backingData;
    int                     backingDataSize;
    uint32_t                imageType;
    char*                   imageVersion;
    ImageProductionType    imageProductionType;
    uint32_t                imageHardwareEpoch;
    uint32_t                imageChipType;
    uint32_t                imageBoardType;
   /* uint8_t*                imageAESKey;
    uint8_t*                imageAESIV;*/ // soon
} ImageStruct;

typedef struct {
	uint32_t	itTag;
	uint32_t	itSkipDistance;
	uint32_t	itBufferLength;
	uint8_t	itBuffer[];
} ImageTagHeader;

int imageCheckFromAddress(
        ImageObjectHandle *newHandle,
        vu32 flashAddress, bool shouldEraseFlashOnFail);

uint8_t rootCA[32];

#endif