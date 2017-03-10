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
	kEnclaveEndpointCrypto = 0x0,
	kEnclaveEndpointBluetooth = 0x1,
	kEnclaveEndpointHost = 0x2
} endpoints_t;

typedef enum opcodes {
	kEnclaveOpcodeDecrypt = 0x0,
	kEnclaveOpcodeEncrypt = 0x1,
	kEnclaveOpcodeObliterateKeys = 0x2
} opcodes_t;

typedef enum tags {
	kEnclaveTagSuperUser = 0x0,
	kEnclaveTagUser = 0x1,
	kEnclaveTagQuery = 0x2
} tags_t;


typedef enum status {
	kEnclaveStatusOpcodeInvalid = 0x0,
	kEnclaveStatusEndpointInvalid = 0x1,
	kEnclaveStatusTagInvalid = 0x2,
	kEnclaveStatusOK = 0x3
} status_t;

/*
	Validate message opcode return 1 if opcode isnt recognized
*/
int validate_opcode(uint8_t opcode) {
	if ((opcode == kEnclaveTagSuperUser) || (opcode == kEnclaveTagUser) || (opcode == kEnclaveTagQuery)) { return 0; } else { return 1; }
}

/*
	Validate message endpoint return 1 if endpoint isnt recognized
*/
int validate_endpoint(uint8_t endpoint) {
	if ((endpoint == kEnclaveTagSuperUser) || (endpoint == kEnclaveTagUser) || (endpoint == kEnclaveTagQuery)) { return 0; } else { return 1; }
}

/*
	Validate message tag return 1 if tag isnt recognized
*/
int validate_tag(uint8_t tag) {
	if ((tag == kEnclaveTagSuperUser) || (tag == kEnclaveTagUser) || (tag == kEnclaveTagQuery)) { return 0; } else { return 1; }
}

enclave_message_t create_message_package(uint8_t opcode_q, uint8_t endpoint_q, uint8_t tag_q, uint8_t param_q, uint32_t data_q, uint32_t pub_q) {
	enclave_message_t qued_message_t;
	int ret = 0;

	// check opcode validity 
	ret = validate_opcode(opcode_q); 
	if (ret)
	{
		uart_printf("Message opcode is invalid! %s %X\n", __FILE__, __LINE__);
		qued_message_t.status = kEnclaveStatusOpcodeInvalid;
		return qued_message_t;
	}
	qued_message_t.opcode = opcode_q;

	// check endpoint validity
	ret = validate_endpoint(endpoint_q);
	if (ret)
	{
		uart_printf("Message endpoint is invalid! %s %X\n", __FILE__, __LINE__);
		qued_message_t.status = kEnclaveStatusEndpointInvalid;
		return qued_message_t;
	}
	qued_message_t.endpoint = endpoint_q;

	// check tag validity
	ret = validate_endpoint(tag_q);
	if (ret)
	{
		uart_printf("Message tag is invalid! %s %X\n", __FILE__, __LINE__);
		qued_message_t.status = kEnclaveStatusTagInvalid;
		return qued_message_t;
	}
	qued_message_t.tag = tag_q;

	/* TODO: check these value's integrity */
	qued_message_t.param = param_q;
	qued_message_t.data = data_q;
	qued_message_t.pub = pub_q;
	qued_message_t.status = kEnclaveStatusOK;

	return qued_message_t;
}

void debug_print_enclave_package(struct enclave_message pkg) {
  uart_printf("Mailbox:\n\tEndpoint: 0x%X\n\tOpcode: 0x%X\n\tTag: 0x%X\n\tParams: 0x%X\n\tData: 0x%X\n\tPub: 0x%X\n", pkg.endpoint, pkg.opcode, pkg.tag, pkg.param, pkg.data, pkg.pub);
}

void mailboxTestSend() {
#if DEBUG
	enclave_message_t package_t = create_message_package(0x02, 0x00, 0x00, 0x00, 0x12345678, 0x12345678);
  	if (package_t.status == kEnclaveStatusOK)
  	{
  		debug_print_enclave_package(package_t);
  	}
#endif
}
