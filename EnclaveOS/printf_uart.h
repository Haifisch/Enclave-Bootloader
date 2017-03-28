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

#include "stm32f10x.h"

#ifdef DEBUG
    #define debug_print(fmt, ...) \
            do { if (DEBUG) uart_printf(fmt , ## __VA_ARGS__); } while (0)
#else
    #define debug_print(fmt, ...)
#endif

void uart_printf(const char *fmt, ...); 
void print_hash(unsigned char hash[]);

void usart_init(void);

