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

#include <stdint.h>
#include <string.h>

#include "mailbox.h"

typedef enum endpoints {
	kEnclaveEndpointCrypto = 0,
	kEnclaveEndpointBluetooth = 1,
	kEnclaveEndpointHost = 2
} endpoints_t;

typedef enum opcodes {
	kEnclaveOpcodeDecrypt = 0x00,
	kEnclaveOpcodeEncrypt = 0x01,
	kEnclaveOpcodeObliterateKeys = 0x02
} opcodes_t;

typedef enum tags {
	kEnclaveTagSuperUser = 0x00,
	kEnclaveTagUser = 0x01,
	kEnclaveTagQuery = 0x02
} tags_t;

/*
	Validate message opcode return 1 if opcode isnt recognized
*/
int validate_opcode(uint8_t opcode) {
	int returnCode;
	switch (opcode) {
		case kEnclaveOpcodeDecrypt:
			returnCode = 0;
			break;

		case kEnclaveOpcodeEncrypt:
			returnCode = 0;
			break;

		case kEnclaveOpcodeObliterateKeys:
			returnCode = 0;
			break; 

		default:
			returnCode = 1;
			break;
	}
	return returnCode;
}

/*
	Validate message endpoint return 1 if opcode isnt recognized
*/
int validate_endpoint(uint8_t endpoint) {
	int returnCode;
	switch (endpoint) {
		case kEnclaveEndpointCrypto:
			returnCode = 0;
			break;

		case kEnclaveEndpointBluetooth:
			returnCode = 0;
			break;

		case kEnclaveEndpointHost:
			returnCode = 0;
			break; 

		default:
			returnCode = 1;
			break;
	}
	return returnCode;
}

/*
	Validate message tag return 1 if opcode isnt recognized
*/
int validate_tag(uint8_t tag) {
	int returnCode;
	switch (tag) {
		case kEnclaveTagSuperUser:
			returnCode = 0;
			break;

		case kEnclaveTagUser:
			returnCode = 0;
			break;

		case kEnclaveTagQuery:
			returnCode = 0;
			break; 

		default:
			returnCode = 1;
			break;
	}
	return returnCode;
}

enclave_message_t create_message_package(uint8_t opcode_q, uint8_t endpoint_q, uint8_t tag_q, uint8_t param_q, uint32_t data_q, uint32_t pub_q) {
	enclave_message_t qued_message_t;
	int ret = 0;

	// check opcode validity 
	ret = validate_opcode(opcode_q); 
	if (ret)
	{
		uart_printf("Message opcode is invalid! %s %X", __FILE__, __LINE__);
	}
	qued_message_t.opcode = opcode_q;

	// check endpoint validity
	ret = validate_endpoint(endpoint_q);
	if (ret)
	{
		uart_printf("Message endpoint is invalid! %s %X", __FILE__, __LINE__);
	}
	qued_message_t.endpoint = endpoint_q;

	// check tag validity
	ret = validate_endpoint(tag_q);
	if (ret)
	{
		uart_printf("Message tag is invalid! %s %X", __FILE__, __LINE__);
	}
	qued_message_t.tag = tag_q;

	qued_message_t.param = param_q;
	qued_message_t.data = data_q;
	qued_message_t.pub = pub_q;

	return qued_message_t;
}

void debug_print_enclave_package(struct enclave_message pkg) {
  uart_printf("Mailbox:\n\tEndpoint: 0x%X\n\tOpcode: 0x%X\n\tTag: 0x%X\n\tParams: 0x%X\n\tData: 0x%X\n\tPub: 0x%X\n", pkg.endpoint, pkg.opcode, pkg.tag, pkg.param, pkg.data, pkg.pub);
}

void mailboxTestSend() {
  enclave_message_t package_t = create_message_package(0x02, 0x00, 0x00, 0x00, 0x12345678, 0x12345678);
  if (DEBUG)
  {
    debug_print_enclave_package(package_t);
  }
}
