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

#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>
#include <string.h>
#include <TEEencrypt_ta.h>
int rootKey;

TEE_Result TA_CreateEntryPoint(void)
{
	DMSG("has been called");

	return TEE_SUCCESS;
}


void TA_DestroyEntryPoint(void)
{
	DMSG("has been called");
}


TEE_Result TA_OpenSessionEntryPoint(uint32_t param_types,
		TEE_Param __maybe_unused params[4],
		void __maybe_unused **sess_ctx)
{
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE);

	DMSG("has been called");

	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	/* Unused parameters */
	(void)&params;
	(void)&sess_ctx;

	
	IMSG("Hello World!\n");


	return TEE_SUCCESS;
}


void TA_CloseSessionEntryPoint(void __maybe_unused *sess_ctx)
{
	(void)&sess_ctx; /* Unused parameter */
	IMSG("Goodbye!\n");
}

//encrypt function
static TEE_Result enc_value(uint32_t param_types,
	TEE_Param params[4])
{
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INOUT,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE);

	char * in = (char *)params[0].memref.buffer;
	int in_len = strlen(params[0].memref.buffer);
	char encrypted [64]={0,};
	
	printf("in enc_value\n");

	//make randomKey
	int randomKey;
	
	TEE_GenerateRandom(&randomKey,sizeof(randomKey));
	while(randomKey<=0){
		TEE_GenerateRandom(&randomKey,sizeof(randomKey));
	}
	//not over 26
	randomKey = randomKey % 26;
	DMSG("random key = %d\n",randomKey);

	//encrypt randomKey with rootKey
	params[1].value.a = randomKey + rootKey;

	DMSG("========================Encryption========================\n");
	DMSG ("Plaintext :  %s", in);
	memcpy(encrypted, in, in_len);

	for(int i=0; i<in_len;i++){
		if(encrypted[i]>='a' && encrypted[i] <='z'){
			encrypted[i] -= 'a';
			encrypted[i] += randomKey;
			encrypted[i] = encrypted[i] % 26;
			encrypted[i] += 'a';
		}
		else if (encrypted[i] >= 'A' && encrypted[i] <= 'Z') {
			encrypted[i] -= 'A';
			encrypted[i] += randomKey;
			encrypted[i] = encrypted[i] % 26;
			encrypted[i] += 'A';
		}
	}
	
	DMSG ("Ciphertext :  %s", encrypted);
	memcpy(in, encrypted, in_len);


	return TEE_SUCCESS;
}

//decrypt function
static TEE_Result dec_value(uint32_t param_types,
	TEE_Param params[4])
{
	char * in = (char *)params[0].memref.buffer;
	int in_len = strlen (params[0].memref.buffer);
	char decrypted [64]={0,};

	//decrypt randomKey
	int encryptKey = params[1].value.a;
	int decryptKey = encryptKey - rootKey;

	DMSG("========================Decryption========================\n");
	DMSG ("Ciphertext :  %s", in);
	DMSG ("key : %d",params[1].value.a);
	memcpy(decrypted, in, in_len);

	for(int i=0; i<in_len;i++){
		if(decrypted[i]>='a' && decrypted[i] <='z'){
			decrypted[i] -= 'a';
			decrypted[i] -= decryptKey;
			decrypted[i] += 26;
			decrypted[i] = decrypted[i] % 26;
			decrypted[i] += 'a';
		}
		else if (decrypted[i] >= 'A' && decrypted[i] <= 'Z') {
			decrypted[i] -= 'A';
			decrypted[i] -= decryptKey;
			decrypted[i] += 26;
			decrypted[i] = decrypted[i] % 26;
			decrypted[i] += 'A';
		}
	}
	DMSG ("Plaintext :  %s", decrypted);
	memcpy(in, decrypted, in_len);
	return TEE_SUCCESS;
}


TEE_Result TA_InvokeCommandEntryPoint(void __maybe_unused *sess_ctx,
			uint32_t cmd_id,
			uint32_t param_types, TEE_Param params[4])
{
	(void)&sess_ctx; /* Unused parameter */
	rootKey = 3;
	printf("cmd_id : %d\n",cmd_id);
	switch (cmd_id) {
	case TA_TEEencrypt_CMD_ENC_VALUE:
		return enc_value(param_types, params);
	case TA_TEEencrypt_CMD_DEC_VALUE:
		return dec_value(param_types, params);
	default:
		return TEE_ERROR_BAD_PARAMETERS;
	}
}
