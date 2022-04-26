/*
 * Copyright (c) 2016, Linaro Limited
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <err.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

/* OP-TEE TEE client API (built by optee_client) */
#include <tee_client_api.h>

/* To the the UUID (found the the TA's h-file(s)) */
#include <TEEencrypt_ta.h>
#define len 64

int main(int argc, char *argv[])
{
	TEEC_Result res;
	TEEC_Context ctx;
	TEEC_Session sess;
	TEEC_Operation op;
	TEEC_UUID uuid = TA_TEEencrypt_UUID;
	uint32_t err_origin;

	char plaintext[64] = {0, };
	char ciphertext[64] = {0, };
	int key;

	res = TEEC_InitializeContext(NULL, &ctx);
	res = TEEC_OpenSession(&ctx, &sess, &uuid,
			       TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);
	
	memset(&op, 0, sizeof(op));

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_OUTPUT, TEEC_NONE, TEEC_NONE, TEEC_NONE);
	op.params[0].tmpref.buffer = plaintext;
	op.params[0].tmpref.size = len;
	op.params[1].value.a=0;

	// if TEEencrypt -e [file]
	if (strcmp(argv[1], "-e") == 0){
		printf("==============================Encryption==============================\n");
		
		//read file
		FILE *fp;
		fp = fopen(argv[2], "r");
		if (fp == NULL){
			printf("Failed to open file.\n");
			exit(0);
		}

		//printing plaintext
		fread(plaintext,1,len, fp);
		fclose(fp);
		printf("plaintext : %s\n", plaintext);
		memcpy(op.params[0].tmpref.buffer, plaintext, len);


		//make encryption
		res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_ENC_VALUE, &op, &err_origin);
		
		//fail making encryption
		if (res != TEEC_SUCCESS){
			errx(1, "TEEC_InvokeCommand failed with code 0x%x origin 0x%x", res, err_origin);
		}

		//print ciphertext
		memcpy (ciphertext, op.params[0].tmpref.buffer, len);
		printf("Ciphertext : %s\n", ciphertext);
		
		
		//make cipher textfile
		fp = fopen("ciphertext.txt", "w");
		fputs(ciphertext, fp);
		fclose(fp);
		//make randomKey textfile
		fp = fopen("key.txt", "w");
		key = op.params[1].value.a;
		fprintf(fp,"%d",key);
		fclose(fp);
	

	}
	else if (strcmp(argv[1], "-d") == 0){
		printf("==============================Decryption==============================\n");
		
		op.params[0].tmpref.buffer = ciphertext;
		op.params[0].tmpref.size = len;
		op.params[1].value.a=0;

		//read file
		FILE *fp;
		fp = fopen(argv[2], "r");
		if (fp == NULL){
			printf("Failed to open ciphertext file.\n");
			exit(0);
		}

		//printing plaintext
		fread(ciphertext,1,len, fp);
		fclose(fp);
		printf("Ciphertext : %s\n", ciphertext);
		memcpy(op.params[0].tmpref.buffer, ciphertext, len);

		fp =fopen(argv[3],"r");
		if (fp == NULL){
			printf("Failed to open keytext file.\n");
			exit(0);
		}
		fscanf(fp, "%d", &key);
		fclose(fp);
		op.params[1].value.a=key;

	
		//make decryption
		res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_DEC_VALUE, &op, &err_origin);
		
		//fail making decryption
		if (res != TEEC_SUCCESS){
			errx(1, "TEEC_InvokeCommand failed with code 0x%x origin 0x%x", res, err_origin);
		}

		//print plaintext
		memcpy (plaintext, op.params[0].tmpref.buffer, len);
		printf("Plaintext : %s\n", plaintext);
		
		
		//make plaintext file
		fp = fopen("plaintext.txt", "w");
		fputs(plaintext, fp);
		fclose(fp);
	
	}


	TEEC_CloseSession(&sess);

	TEEC_FinalizeContext(&ctx);

	return 0;
}
