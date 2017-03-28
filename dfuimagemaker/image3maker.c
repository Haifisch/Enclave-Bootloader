/*
 * Copyright 2013, winocm. <winocm@icloud.com>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 *
 *   Redistributions of source code must retain the above copyright notice, this
 *   list of conditions and the following disclaimer.
 *
 *   Redistributions in binary form must reproduce the above copyright notice, this
 *   list of conditions and the following disclaimer in the documentation and/or
 *   other materials provided with the distribution.
 *
 *   If you are going to use this software in any form that does not involve
 *   releasing the source to this project or improving it, let me know beforehand.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
 * ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/* THIS UTILITY NEEDS TO BE REDONE PROPERLY !!! */
/* cc -O2 -pipe image3maker.c -o image3maker */



 /* 
    This is really really hacked up code, stripped everything we didn't need in our image format. 
    thanks winocm <3
    ~ love,
        haifisch    
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <getopt.h>
#include <stdint.h>
#include <assert.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/errno.h>

#include "edsign.h"
#include "sha256.h"
#include "cdecode.h"

#define SHA256_DIGEST_LENGTH 32

typedef enum {
    IMAGE_PROD_DEVELOPMENT = 0,
    IMAGE_PROD_PRODUCTION = 1,
} ImageProductionType;

#define kImageMagic             'Ebc2'

/* Image types */
#define kImageTypeKernel            'enos'

/* Image3 Tags */
#define kImageTagData               'DATA'
#define kImageTagType               'TYPE'
#define kImageTagCert               'CERT'
#define kImageTagSignature          'EDSN'
#define kImageTagBoard              'BORD'
#define kImageTagECID              'ECID'
#define kImageTagVersion       'VERS'      /* string */
#define kImageTagProduct           'PROD'

typedef struct _ImageObjectHeader {
    uint32_t    ihMagic;
#define kImageHeaderMagic       'Ebc2'
    uint32_t    ihSkipDistance;
    uint32_t    ihBufferLength;

    uint32_t    ihSignedLength;
    uint32_t    ihType;
    uint8_t ihBuffer[];
} ImageObjectHeader;

typedef struct _ImageInternalState {
    ImageObjectHeader       *image;
    uint32_t            flags;
# define kImageImageWasInstantiated 0x1
# define kImageImageRejectSignature 0x2
# define kImageImageIsTrusted       0x3 
# define kImageImageMissingMagic    0x4
# define kImageImageHashCalcFailed  0x5
    size_t              allocSize;

    int             cursor;
    int             lastTag;
} ImageInternalState;

struct _ImageInternalState;
typedef struct _ImageInternalState  *ImageObjectHandle;

uint8_t rootCA[32] = {
       0xbd, 0x0c, 0x2d, 0x04, 0x2e, 0x5a, 0x95, 0xc6, 0xb6, 0x28, 0xfc, 0x3f, 0x85, 0x6c, 0xa1, 0xfb, 0xb5, 0x25, 0x07, 0x38, 0xc0, 0x05, 0x9d, 0x44, 0x04, 0xa7, 0xe3, 0xa6, 0xac, 0x3b, 0xb8, 0x41
    };

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

#define add_ptr2(x, y)      ((uintptr_t)((uintptr_t)x + (uintptr_t)y))

#define PROGRAM_NAME    "image3maker"

ImageStruct image3core;

static char *inputFile = NULL, *outputFile = NULL, *imageTag = NULL;
static char *imageVersion = NULL, *imageDomain = NULL, *imageProduction = NULL;
static char *hardwareEpoch = NULL, *chipType = NULL, *boardType = NULL;
static char *uniqueIdentifier = NULL, *aesKey = NULL, *aesIv = NULL;
static char *certificateBlob = NULL, *imageSecurityEpoch = NULL;
static bool dontHashInECIDPlease = 0;
static bool testVerifyImage = 0; 
static inline void hex_to_bytes(const char* hex, uint8_t** buffer, size_t* bytes) {
	*bytes = strlen(hex) / 2;
	*buffer = (uint8_t*) malloc(*bytes);
	size_t i;
	for(i = 0; i < *bytes; i++) {
		uint32_t byte;
		sscanf(hex, "%2x", &byte);
		(*buffer)[i] = byte;
		hex += 2;
	}
}

static void print_hex(const char *label, const uint8_t *data, int len)
{
    int i;

    printf("%s: ", label);
    for (i = 0; i < len; i++)
        printf("0x%02x, ", data[i]);
    printf("\n");
}

void print_hash(unsigned char hash[])
{
   int idx;
   for (idx=0; idx < 32; idx++)
      printf("%02x",hash[idx]);
   printf("\n");
}

size_t decode_b64(const char* input, char* output)
{
    base64_decodestate s;
    size_t cnt;

    base64_init_decodestate(&s);
    cnt = base64_decode_block(input, strlen(input), output, &s);
    output[cnt] = 0;

    return cnt;
}

int calc_sha256 (char* path, unsigned char output[SHA256_DIGEST_LENGTH])
{
    FILE* file = fopen(path, "rb");
    if(!file) return -1;

    sha256_context sha256;
    sha256_starts(&sha256);
    const int bufSize = 5;
    char* buffer = malloc(bufSize);
    int bytesRead = 0;
    if(!buffer) return -1;
    while((bytesRead = fread(buffer, 1, bufSize, file)))
    {
        sha256_update(&sha256, buffer, bytesRead);
    }   
    if (!dontHashInECIDPlease)
    {
        unsigned char decodedPublickey[32];
        decode_b64(uniqueIdentifier, decodedPublickey);
        print_hex("PUB", decodedPublickey, 32);
        sha256_update(&sha256, decodedPublickey, 32);
    }
    sha256_finish(&sha256, output);

    fclose(file);
    free(buffer);
    return 0;
}      

static void* map_file(char *path, int *size)
{
	FILE *f;
    long sz;
    void *p;
    
    assert((f = fopen(path, "rb")));
    
    fseek(f, 0, SEEK_END);
    sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    assert(sz);
    
    assert((p = malloc(sz)) != NULL);
    assert((sz != (fread(p, sz, 1, f))));
    
    assert(size);
    *size = (int)sz;
    
	return p;
}

static void print_usage(void)
{
    printf("Usage: %s [options]\n\n", PROGRAM_NAME);
    printf("Generate an Image3 file.\n"
           "\n"
           "  -f, --dataFile [file]               Use file as an input. (required)\n"
           "  -t, --imageTag [tag]                4-byte ASCII tag for image (required)\n"
           "  -v, --imageVersion [version]        Set version string\n"
           "  -p, --imageProduction [prodValue]   Mark image production value (production/development)\n"
           "  -e, --uniqueIdentifier [uniqueID]   Set ECID for image\n"
           "  -a, --aesKey [aesKey]               Set AES key for image encryption (implies -i/--aesIv)\n"
           "  -i, --aesIv [aesIv]                 Set AES IV for image encryption (implies -a/--aesKey)\n"
           "  -o, --outputFile [file]             Output image3 file\n"
           "\n"
           "Only AES256 keybags are supported by this program right now.\n"
           "Have fun using this thingy. (ALL VALUES FOR THINGS SHOULD BE IN HEX!!!)\n");
    exit(-1);
    return;
}

static uint32_t fourcc_to_uint(char* str)
{
    uint32_t out;
    assert(strlen(str) == 4);
    out = __builtin_bswap32(*(uint32_t*)str);
    return out;
}

static inline int round_up(int n, int m)
{
    return (n + m - 1) & ~(m - 1);
}

int verify_test (ImageObjectHandle *newHandle) {
    FILE *fp = fopen(inputFile, "r");
    printf("Verifying image\n");
    ImageRootHeader     *hdr;
    ImageInternalState      state;
    int bufferSize = 0x28+0x40;
    unsigned char imageBuffer[bufferSize];
    memset(imageBuffer, 0xFF, sizeof(imageBuffer));
    fread(imageBuffer, sizeof(char), bufferSize, fp);
    memset(&state, 0, sizeof(state));

    hdr = (ImageRootHeader *)imageBuffer;

    if (bufferSize < sizeof(hdr)) {
        printf("buffer size %X too small for header size %X\n", bufferSize, sizeof(*hdr));
        return(EINVAL);     /* buffer too small to really contain header */
    }
    if ((hdr->header.magic) != kImageHeaderMagic) {
        printf("bad magic 0x%08x expecting 0x%08x\n", (hdr->header.magic), kImageHeaderMagic);
        state.flags = kImageImageMissingMagic;
        *newHandle = &state;
        return(kImageImageMissingMagic);        /* magic must match */
    }
    if ((hdr->signing.imageType) != 0x45444f53)
    {
        printf("bad magic 0x%08x expecting 0x%X\n", (hdr->signing.imageType), 0x45444f53);
        state.flags = kImageImageMissingMagic;
        *newHandle = &state;
        return(kImageImageMissingMagic);        /* magic must match */
    }
    state.flags = kImageImageWasInstantiated;

    printf("dataSize: 0x%X\n", (hdr->header.dataSize));

    state.cursor = hdr->header.dataSize;
    state.lastTag = -1;

    char sha256sum[32];

    memset(sha256sum, 0xFF, sizeof(sha256sum));

    sha256_context ctx;
    sha256_starts(&ctx);

    int buffSize = (hdr->header.dataSize);
    char buff[buffSize];

    //int i = 0x84;
    //char cmpEnd[5] = {0x01, 0x00, 0x00, 0x00, 0x00}; 
    fseek(fp, 0, SEEK_SET);
    fseek(fp, 0x84, SEEK_CUR);
    //int finish = hdr->header.dataSize + 0x84;
    
    fread(buff, (hdr->header.dataSize), 1, fp);
    print_hex("DATA", buff, 0x20);
    sha256_update(&ctx, buff, buffSize);

    char uniqueID = uniqueIdentifier;
    if (!dontHashInECIDPlease)
    {
        printf("Hashing in ECID\n");
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
static void *image3_reserve_version(uint32_t tag, uint32_t length)
{
    uint32_t size, len;
    ImageHeader* header;

    /* Make it even */
    len = (uint32_t)round_up(length + sizeof(ImageHeader), 2);
    size = (uint32_t)round_up(image3core.rootHeader->header.size + len, 16);
    
    /* Padding */
    len += ((uint32_t)round_up(image3core.rootHeader->header.size + len, 16) -
            (uint32_t)round_up(image3core.rootHeader->header.size + len, 2));
    
    /* APPLE.. */
    len -= 4;
    size -= 4;
    
    assert((image3core.rootHeader = realloc(image3core.rootHeader, size)));
    
    header = (ImageHeader*)add_ptr2(image3core.rootHeader, image3core.rootHeader->header.size);
    bzero((void*)(header), len);

    header->dataSize = length;
    header->size = len;
    header->magic = tag;
    
    image3core.rootHeader->header.size = size;    
    return (void*)(header + 1);
}

static void *image3_reserve_data(uint32_t tag, uint32_t length)
{
    uint32_t size, len;
    ImageHeader* header;
    
    /* Make it even */
    len = (uint32_t)round_up(length + sizeof(ImageHeader), 2);
    size = (uint32_t)round_up(image3core.rootHeader->header.size + len, 16);
    
    /* Padding */
    len += ((uint32_t)round_up(image3core.rootHeader->header.size + len, 16) -
            (uint32_t)round_up(image3core.rootHeader->header.size + len, 2));
    
    assert((image3core.rootHeader = realloc(image3core.rootHeader, size)));
    
    header = (ImageHeader*)add_ptr2(image3core.rootHeader, image3core.rootHeader->header.size);
    bzero((void*)(header), len);

    header->dataSize = length;
    header->size = len;
    header->magic = tag;
    
    image3core.rootHeader->header.size = size;
    
    return (void*)(header + 1);
}

/* This is for other tags other than data. Apple is weird like this. */
static void *image3_reserve_tag(uint32_t tag, uint32_t length)
{
    uint32_t size, len;
    ImageHeader* header;
    
    len = length + 24;
    size = image3core.rootHeader->header.size + len;
    
    assert((image3core.rootHeader = realloc(image3core.rootHeader, size)));
    
    header = (ImageHeader*)add_ptr2(image3core.rootHeader, image3core.rootHeader->header.size);
    bzero((void*)(header), len);

    header->dataSize = length;
    header->size = len;
    header->magic = tag;
    
    image3core.rootHeader->header.size = size;    
    
    return (void*)(header + 1);
}

/* This is for other tags other than data. Apple is weird like this. */
static void *image3_reserve_ecid(uint32_t tag, uint32_t length)
{
    uint32_t size, len;
    ImageHeader* header;
    
    len = length + 20;
    size = image3core.rootHeader->header.size + len;
    
    assert((image3core.rootHeader = realloc(image3core.rootHeader, size)));
    
    header = (ImageHeader*)add_ptr2(image3core.rootHeader, image3core.rootHeader->header.size);
    bzero((void*)(header), len);

    header->dataSize = length;
    header->size = len;
    header->magic = tag;
    
    image3core.rootHeader->header.size = size;
    return (void*)(header + 1);
}

/* This is to make sure the DATA is always at 0x40. */
static void *image3_reserve_type(uint32_t tag, uint32_t length)
{
    uint32_t size, len;
    ImageHeader* header;
    
    len = length + 28;
    size = image3core.rootHeader->header.size + len;
    
    assert((image3core.rootHeader = realloc(image3core.rootHeader, size)));
    
    header = (ImageHeader*)add_ptr2(image3core.rootHeader, image3core.rootHeader->header.size);
    header->dataSize = length;
    header->size = len;
    header->magic = tag;
    
    image3core.rootHeader->header.size = size;
    return (void*)(header + 1);
}



static void create_image(void)
{
    printf("Creating image of type \'%s\' (0x%08x)...\n", imageTag, image3core.imageType);

    assert((image3core.rootHeader = malloc(sizeof(ImageRootHeader))));
    
    image3core.rootHeader->header.magic = kImageMagic;    
    image3core.rootHeader->header.size = sizeof(ImageRootHeader);
    image3core.rootHeader->signing.imageType = image3core.imageType;
    
    FILE *fp = fopen(inputFile, "rb");
    fseek(fp, 0L, SEEK_END);
    image3core.rootHeader->header.dataSize = ftell(fp);
    fclose(fp);

    unsigned char calc_hash[32];

    calc_sha256(inputFile, calc_hash);
    printf("Calculated file hash: ");
    print_hash(calc_hash);

    uint8_t secret[32] = {0xc1, 0xb4, 0xaf, 0x1f, 0xfc, 0x27, 0x24, 0x8b, 0x42, 0x0b, 0x0c, 0x3f, 0x3f, 0x38, 0xd4, 0x4a, 
                          0x2d, 0xb2, 0x4e, 0x03, 0xa0, 0x8c, 0x20, 0x91, 0x9e, 0xfa, 0x68, 0x17, 0x8b, 0xa0, 0x5a, 0x67};

    uint8_t pub[EDSIGN_PUBLIC_KEY_SIZE];
    uint8_t msg[32];
    uint8_t signature[EDSIGN_SIGNATURE_SIZE];

    edsign_sec_to_pub(pub, secret);

    print_hex("Secret", secret, sizeof(secret));
    print_hex("Public", pub, sizeof(pub));

    //memcpy(msg, calc_hash, 32);

    print_hex("Hash to sign", calc_hash, sizeof(calc_hash));
    edsign_sign(signature, pub, secret, calc_hash, 32);

    assert(edsign_verify(signature, pub, calc_hash, 32));

    memcpy(image3core.rootHeader->signing.imageSignature, signature, EDSIGN_SIGNATURE_SIZE);


    /* DATA/TYPE tags */
    uint32_t* type;
    void* data;
    uint8_t* sig;
    
    type = image3_reserve_type(kImageTagType, sizeof(uint32_t));
    *type = image3core.imageType;
    
    data = image3_reserve_data(kImageTagData, image3core.backingDataSize);
    memcpy(data, image3core.backingData, image3core.backingDataSize);
    
    /* Other tags */
    if(imageVersion) {
        printf("Image Version:    %s\n", imageVersion);

        void* version;
        uint32_t *length;
        version = image3_reserve_version(kImageTagVersion, (uint32_t)strlen(imageVersion) + 4);
        length = (uint32_t*)version;
        *(length) = (uint32_t)strlen(imageVersion);
        strncpy((char*)version + sizeof(uint32_t), imageVersion, strlen(imageVersion));
    }

    if(imageProduction) {
        printf("Production Type:  0x%08x\n", image3core.imageProductionType);
        
        uint32_t *imageProd = image3_reserve_tag(kImageTagProduct, sizeof(uint32_t));
        *imageProd = image3core.imageProductionType;
    }
    /*
    if(uniqueIdentifier) {
        printf("ECID:             0x%X\n", image3core.imageUniqueIdentifier);
        
        //uint32_t *ecid = image3_reserve_ecid(kImageTagECID, 23);
        //*ecid = image3core.imageUniqueIdentifier;
    }
    */
    /* AES stuff... TODO */

    printf("Total Size:       0x%X bytes\n", image3core.rootHeader->header.size);
    printf("Data Size:        0x%X bytes\n", image3core.rootHeader->header.dataSize);
    print_hex("Signature", image3core.rootHeader->signing.imageSignature, sizeof(image3core.rootHeader->signing.imageSignature));
}

static void output_image(void)
{
    FILE *f;
    assert((f = fopen(outputFile, "wb+")));
    assert(image3core.rootHeader->header.size != fwrite(image3core.rootHeader, image3core.rootHeader->header.size, 1, f));
    fclose(f);
}

static void create_image_preprocess(void)
{
    assert(inputFile && imageTag && outputFile);
    
    bzero((void*)&image3core, sizeof(ImageStruct));
    
    /* Read input file */
    image3core.backingData = map_file(inputFile, &image3core.backingDataSize);
    assert(image3core.backingDataSize);
    
    /* Image tag */
    image3core.imageType = fourcc_to_uint(imageTag);
    
    /* Other stuff. */
    image3core.imageVersion = imageVersion;

    /* PROD */
    if(imageProduction) {
        /* lol buffer overflow */
        if(!strcasecmp(imageProduction, "production"))
            image3core.imageProductionType = IMAGE_PROD_PRODUCTION;
        else if(!strcasecmp(imageProduction, "development"))
            image3core.imageProductionType = IMAGE_PROD_DEVELOPMENT;
        else {
            printf("invalid production type '%s'\n", imageProduction);
            exit(-1);
        }
    }
    
    /* Other stuff
    if(uniqueIdentifier) {
        image3core.imageUniqueIdentifier = (uint32_t)uniqueIdentifier;
    }
    */
    /* AES key/iv 
    if(aesKey && aesIv) {
        size_t szKey, szIv;
        hex_to_bytes(aesKey, &image3core.imageAESKey, &szKey);
        hex_to_bytes(aesIv, &image3core.imageAESIV, &szIv);
        assert((szKey == 32) && (szIv == 16));
    }
    */
    return;
}

static int process_options(int argc, char* argv[])
{
    int c = 0;
    
    while(1) {
        static struct option user_options[] = {
            {"dataFile",        required_argument, 0, 'f'},
            {"imageTag",        required_argument, 0, 't'},
            {"imageVersion",    required_argument, 0, 'v'},
            {"imageProduction", required_argument, 0, 'p'},
            {"uniqueIdentifier", required_argument, 0, 'e'},
            {"dontHashInECID", required_argument, 0, 'q'},
            {"aesKey",          required_argument, 0, 'a'},
            {"aesIv",           required_argument, 0, 'i'},
            {"outputFile",      required_argument, 0, 'o'},
            {"testVerifyImage",      required_argument, 0, 'g'},
            {"help", no_argument, 0, '?'},
        };
        int option_index = 0;
        
        c = getopt_long(argc, argv, "c:f:t:v:d:p:h:y:b:s:e:q:g:a:i:o:",
                        user_options, &option_index);
        
        if(c == -1)
            break;
        
        switch(c) {
            case 's':
                imageSecurityEpoch = optarg;
                break;
            case 'c':
                certificateBlob = optarg;
                break;
            case 'f':
                inputFile = optarg;
                break;
            case 'o':
                outputFile = optarg;
                break;
            case 't':
                imageTag = optarg;
                break;
            case 'v':
                imageVersion = optarg;
                break;
            case 'q':
                dontHashInECIDPlease = 1;
                break;
            case 'd':
                imageDomain = optarg;
                break;
            case 'p':
                imageProduction = optarg;
                break;
            case 'h':
                hardwareEpoch = optarg;
                break;
            case 'y':
                chipType = optarg;
                break;
            case 'b':
                boardType = optarg;
                break;
            case 'e':
                uniqueIdentifier = optarg;
                break;
            case 'a':
                aesKey = optarg;
                break;
            case 'i':
                aesIv = optarg;
                break;
            case 'g':
                testVerifyImage = 1;
                break;
            default:
                print_usage();
                break;
        }
    }
    
    if(!inputFile) {
        printf("No input file\n");
        print_usage();
    }
    
    if(!outputFile && !testVerifyImage) {
        printf("No output file\n");
        print_usage();
    }
    
    if(!imageTag && !testVerifyImage) {
        printf("No image tag\n");
        print_usage();
    }
    
    return 0;
}

int main(int argc, char* argv[])
{
    process_options(argc, argv);
    if (testVerifyImage)
    {
        ImageObjectHandle imageHandle;
        int i = verify_test(&imageHandle);
        printf("image check ret: 0x%X\n", i);
        switch (i)
        {
            case kImageImageIsTrusted:
                printf("Boot OK\n");
                break;

            case kImageImageMissingMagic:
                printf("Firmware missing...\n");
                break;

            case kImageImageRejectSignature:
                printf("Signature unverified...\n");
                break;

            case kImageImageHashCalcFailed:
                printf("Hash calculation failed...\n");
                break;
                
            default:
                break;
        }
    } else {
        create_image_preprocess();
        create_image();
        output_image();
    }
    return 0;
}

