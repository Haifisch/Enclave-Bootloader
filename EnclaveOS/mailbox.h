/*
 * Copyright (C) 2016 Sun Tzu Security, LLC. All rights reserved.
 *
 * This document is the property of Sun Tzu Security, LLC.
 * It is considered confidential and proprietary.
 *
 * This document may not be reproduced or transmitted in any form,
 * in whole or in part, without the express written permission of
 * Sun Tzu Security, LLC.
 */

typedef struct enclave_message {
	uint8_t		status;
	uint8_t		endpoint;
	uint8_t		tag;
	uint8_t		opcode;
	uint8_t		param;
	uint32_t	data;
	uint32_t	pub;
} __attribute__((packed)) enclave_message;

typedef struct enclave_message enclave_message_t;

enclave_message_t create_message_package(uint8_t opcode_q, uint8_t endpoint_q, uint8_t tag_q, uint8_t param_q, uint32_t data_q, uint32_t pub_q);

void mailboxTestSend();