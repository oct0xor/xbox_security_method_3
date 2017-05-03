// Copyright (C) 2013 oct0xor
// 
// This program is free software : you can redistribute it and / or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, version 2.0.
// 
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.See the
// GNU General Public License 2.0 for more details.
// 
// A copy of the GPL 2.0 should have been included with the program.
// If not, see http ://www.gnu.org/licenses/

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "des.h"
#include "sha1.h"
#include "utils.h"

/* Important note: CamelCase names fetched from debug symbols */

unsigned char UsbdSecSboxData[256] = {
	0xB0, 0x3D, 0x9B, 0x70, 0xF3, 0xC7, 0x80, 0x60,
	0x73, 0x9F, 0x6C, 0xC0, 0xF1, 0x3D, 0xBB, 0x40,
	0xB3, 0xC8, 0x37, 0x14, 0xDF, 0x49, 0xDA, 0xD4,
	0x48, 0x22, 0x78, 0x80, 0x6E, 0xCD, 0xE7, 0x00,
	0x81, 0x86, 0x68, 0xE1, 0x5D, 0x7C, 0x54, 0x2C,
	0x55, 0x7B, 0xEF, 0x48, 0x42, 0x7B, 0x3B, 0x68,
	0xE3, 0xDB, 0xAA, 0xC0, 0x0F, 0xA9, 0x96, 0x20,
	0x95, 0x05, 0x93, 0x94, 0x9A, 0xF6, 0xA3, 0x64,
	0x5D, 0xCC, 0x76, 0x00, 0xE5, 0x08, 0x19, 0xE8,
	0x8D, 0x29, 0xD7, 0x4C, 0x21, 0x91, 0x17, 0xF4,
	0xBC, 0x6A, 0xB3, 0x80, 0x83, 0xC6, 0xD4, 0x90,
	0x9B, 0xAE, 0x0E, 0xFE, 0x2E, 0x4A, 0xF2, 0x00,
	0x73, 0x88, 0xD9, 0x40, 0x66, 0xC5, 0xD4, 0x08,
	0x57, 0xB1, 0x89, 0x48, 0xDC, 0x54, 0xFC, 0x43,
	0x6A, 0x26, 0x87, 0xB8, 0x09, 0x5F, 0xCE, 0x80,
	0xE4, 0x0B, 0x05, 0x9C, 0x24, 0xF3, 0xDE, 0xE2,
	0x3E, 0xEC, 0x38, 0x8A, 0xA2, 0x55, 0xA4, 0x50,
	0x4E, 0x4B, 0xE9, 0x58, 0x7F, 0x9F, 0x7D, 0x80,
	0x23, 0x0C, 0x4D, 0x80, 0x05, 0x44, 0x26, 0xB8,
	0xE9, 0xD8, 0xBC, 0xE6, 0x76, 0x3A, 0x6E, 0xA4,
	0x19, 0xDE, 0xC2, 0xD0, 0xC4, 0xBC, 0xC3, 0x5C,
	0x59, 0xDF, 0x16, 0x46, 0x39, 0x70, 0xF4, 0xEE,
	0x2D, 0x58, 0x5A, 0xA8, 0x17, 0x86, 0x6B, 0x60,
	0x29, 0x58, 0x4D, 0xD2, 0x5F, 0x28, 0x7A, 0xD8,
	0x8E, 0x79, 0xEA, 0x82, 0x94, 0x33, 0x31, 0x81,
	0xD9, 0x22, 0xD5, 0x10, 0xDA, 0x92, 0xA0, 0x7D,
	0x3D, 0xDA, 0xAC, 0x1C, 0xA2, 0x53, 0x31, 0xB8,
	0x3C, 0x96, 0x52, 0x00, 0x82, 0x6B, 0x56, 0xA0,
	0xD3, 0xC2, 0x40, 0xC7, 0x1B, 0x7F, 0xDC, 0x01,
	0x72, 0x70, 0xB1, 0x8C, 0x01, 0x09, 0x09, 0x36,
	0xFC, 0x97, 0xEA, 0xDE, 0xE3, 0x0D, 0xAE, 0x7E,
	0xE3, 0x0D, 0xAE, 0x7E, 0x33, 0x69, 0x80, 0x40
};

unsigned char UsbdSecPlainTextData[128] = {
	0xD1, 0xD2, 0xF2, 0x80, 0x6E, 0xBA, 0x0C, 0xC0,
	0xB6, 0xC4, 0xC9, 0xD8, 0x61, 0x75, 0x1D, 0x1A,
	0x3F, 0x95, 0x58, 0xBE, 0xD8, 0x0D, 0xE2, 0xC0,
	0xD0, 0x21, 0x79, 0x20, 0x65, 0x2D, 0x99, 0x40,
	0x3C, 0x96, 0x52, 0x00, 0x1B, 0x7F, 0xDC, 0x01,
	0x82, 0x1C, 0x13, 0xD8, 0x33, 0x69, 0x80, 0x40,
	0xFC, 0x97, 0xEA, 0xDE, 0x08, 0xEA, 0x14, 0xDC,
	0xEB, 0x0F, 0x6A, 0x18, 0x6F, 0x78, 0x2C, 0xB0,
	0xD3, 0xC2, 0x40, 0xC7, 0x82, 0x6B, 0x56, 0xA0,
	0x19, 0x09, 0x36, 0xE0, 0x72, 0x70, 0xB1, 0x8C,
	0xE3, 0x0D, 0xAE, 0x7E, 0x50, 0xA5, 0x2B, 0xE2,
	0xC9, 0xAF, 0xC7, 0x70, 0x1C, 0x29, 0x80, 0x56,
	0x24, 0xF0, 0x66, 0xFA, 0x02, 0x2B, 0x58, 0x98,
	0x8F, 0xE4, 0xD1, 0x3C, 0x6E, 0x38, 0x2A, 0xFF,
	0xB8, 0xFA, 0x35, 0xB0, 0x52, 0x49, 0xC5, 0xB4,
	0x66, 0xFA, 0x47, 0x55, 0x6C, 0x8D, 0x40, 0x08
};

unsigned char ProtocolData[0x20];
unsigned char Random[0x10];
unsigned char Cert[8]; /* ConsoleID */
unsigned char RandomSwap[0x10];
unsigned char RandomEnc[0x10];
unsigned char RandomSwapEnc[0x10];
unsigned char UsbRandom[0x10];
unsigned char UsbCmdHash[0x20];

void UsbdSecXSM3AuthenticationCrypt(unsigned char *key, const unsigned char *input, size_t length, unsigned char *output, int mode) 
{
	des3_context ctx;
	unsigned char sk[0x18];
	unsigned char iv[8];

    memset(iv, 0, 8);

	memcpy(sk, key, 0x10);

	*(unsigned long long*)(sk + 0x10) = *(unsigned long long*)sk;

    if (mode == DES_ENCRYPT)
        des3_set3key_enc(&ctx, (unsigned char *)sk);
    else
        des3_set3key_dec(&ctx, (unsigned char *)sk);

	des3_crypt_cbc(&ctx, mode, length, iv, input, output);
}

void UsbdSecXSM3AuthenticationMac(const unsigned char *key, const unsigned char *salt, unsigned char *input, size_t length, unsigned char *output, int mode) 
{
	des_context des_enc_ctx;
	des_context des_dec_ctx;
	des_context des_enc_ctx2;
	des3_context des3_enc_ctx;
	unsigned char sk[0x18];
	unsigned char iv[8];
	unsigned char temp[8];
	unsigned int i;

	memset(temp, 0, sizeof(temp));

	if (mode)
	{
		des_setkey_enc(&des_enc_ctx, key);

		des_setkey_dec(&des_dec_ctx, key + 8);

		if (salt) 
		{
			*(unsigned long long *)salt = SWAP64(SWAP64(*(unsigned long long *)salt) + 1);

			des_crypt_ecb(&des_enc_ctx, salt, temp);
		}
	}

	if (length >= 8) 
	{
		for (i = 0; i < length / 8; i++)
		{
			*(unsigned long long *)temp ^= *(unsigned long long *)(input + i * 8);

			if (mode) 
			{
				des_crypt_ecb(&des_enc_ctx, temp, temp);
			}
			else 
			{
				des_setkey_enc(&des_enc_ctx2, key);

				des_crypt_ecb(&des_enc_ctx2, temp, temp);
			}
		}
	}

	*(unsigned char *)temp ^= 0x80;

	if (mode) 
	{
		des_crypt_ecb(&des_enc_ctx, temp, temp);

		des_crypt_ecb(&des_dec_ctx, temp, temp);

		des_crypt_ecb(&des_enc_ctx, temp, output);
	}
	else 
	{
		memset(iv, 0, 8);

		memcpy(sk, key, 0x10);

		*(unsigned long long*)(sk + 0x10) = *(unsigned long long*)sk;

		des3_set3key_enc(&des3_enc_ctx, (unsigned char *)sk);

		des3_crypt_cbc(&des3_enc_ctx, DES_ENCRYPT, 8, iv, temp, output);
	}
}

void XeCryptParveEcb(const unsigned char *pbKey, const unsigned char *pbSbox, const unsigned char *pbInp, unsigned char *pbOut) 
{
	unsigned char block[9];
	unsigned char i;
	unsigned char j;
	unsigned char x;
	unsigned char y;

	memcpy(block, pbInp, 8);

	block[8] = block[0];

	for (i = 8; i > 0; i--)
	{
		for (j = 0; j < 8; j++) 
		{
			x = *(unsigned char *)(pbKey + j) + *(unsigned char *)(block + j) + i;

			y = *(unsigned char *)(x + pbSbox) + *(unsigned char *)(block + j + 1);

			*(unsigned char *)(block + j + 1) = ROTL8(y, 1);
		}

		block[0] = block[8];
	}

	memcpy(pbOut, block, 8);
}

void XeCryptParveCbcMac(const unsigned char *pbKey, const unsigned char *pbSbox, const unsigned char *pbIv, const unsigned char *pbInp, size_t cbInp, unsigned char *pbOut) 
{
	unsigned char block[8];
	unsigned int i;

	memcpy(block, pbIv, 8);

	if (cbInp >= 8) 
	{
		for (i = 0; i < cbInp / 8; i++)
		{
			*(unsigned long long *)block ^= *(unsigned long long *)(pbInp + i * 8);

			XeCryptParveEcb(pbKey, pbSbox, block, block);
		}
	}

	memcpy(pbOut, block, 8);
}

void XeCryptChainAndSumMac(const unsigned int *pdwCD, const unsigned int *pdwAB, const unsigned int *pdwInp, unsigned int cdwInp, unsigned int *pdwOut)
{
	unsigned char *p = pdwInp;
	unsigned long long out0 = 0;
	unsigned long long out1 = 0;
	unsigned long long t;

	unsigned int ab0 = SWAP32(pdwAB[0]) % 0x7FFFFFFF;
	unsigned int ab1 = SWAP32(pdwAB[1]) % 0x7FFFFFFF;
	unsigned int cd0 = SWAP32(pdwCD[0]) % 0x7FFFFFFF;
	unsigned int cd1 = SWAP32(pdwCD[1]) % 0x7FFFFFFF;

	for (int i = cdwInp / 2; i > 0; i--)
	{
		t = (unsigned long long)(SWAP32(*(unsigned int *)p)) * 0xE79A9C1;
		t = t + out0;
		t = (t % 0x7FFFFFFF) * ab0;
		t = t + ab1;
		t = t % 0x7FFFFFFF;
		out1 = out1 + t;

		t = (unsigned long long)(SWAP32(*(unsigned int *)(p + 4)) + t) * cd0;
		t = (t % 0x7FFFFFFF) + cd1;
		out0 = t % 0x7FFFFFFF;
		out1 = out1 + out0;

		p += 8;
	}

	pdwOut[0] = SWAP32((out0 + ab1) % 0x7FFFFFFF);
	pdwOut[1] = SWAP32((out1 + cd1) % 0x7FFFFFFF);
}

void UsbdSecXSMAuthenticationAcr(const unsigned char *input, const unsigned char *key, unsigned char *output) 
{
	unsigned char block[8];
	unsigned char iv[8];
	unsigned char ab[8];
	unsigned char cd[8];

	*(unsigned int *)block = *(unsigned int *)input;
	*(unsigned int *)(block + 4) = *(unsigned int *)Cert;

	XeCryptParveEcb(key, UsbdSecSboxData, input + 0x10, iv);

	XeCryptParveEcb(key, UsbdSecSboxData, block, cd);

	XeCryptParveCbcMac(key, UsbdSecSboxData, iv, UsbdSecPlainTextData, 0x80, ab);

	XeCryptChainAndSumMac((unsigned int *)cd, (unsigned int *)ab, (unsigned int *)UsbdSecPlainTextData, 0x20, (unsigned int *)output);

	*(unsigned long long *)output ^= *(unsigned long long *)ab;
}

int chksum(unsigned char *cmd) 
{
	unsigned int length;
	unsigned int chksum = 0;

	length = cmd[4];

	for(int i = 0; i < length; i++)
		chksum ^= cmd[i+5];
	
	if (chksum != cmd[length+5]) 
		return -1;
	
	return 0;
}

void UsbdSecGetIdentificationComplete(unsigned char *protocol_data, unsigned char *cmd) 
{
	memcpy(protocol_data, cmd + 5, 0xF);

	*(unsigned short *)(protocol_data + 0x10) = *(unsigned short *)(cmd + 5 + 0xF);
	*(unsigned short *)(protocol_data + 0x12) = *(unsigned short *)(cmd + 5 + 0x11);
	*(unsigned char *)(protocol_data + 0x14) = *(unsigned char *)(cmd + 5 + 0x13);
	*(unsigned char *)(protocol_data + 0x15) = *(unsigned char *)(cmd + 0x1B); // 5 + 0x16
	*(unsigned short *)(protocol_data + 0x16) = *(unsigned short *)(cmd + 5 + 0x14);
}

int XSM3(void) 
{
	unsigned char decrypted_data[0x20];
	unsigned char mac_copy[8];
	unsigned char mac[8];
	unsigned char random[0x10];
	unsigned char acr_copy[8];
	unsigned char acr[8];
	int result = 0;

	/* sniffed usb traffic */

	unsigned char UsbdSecXSM3GetIdentificationProtocolData[29] = {
		0x49, 0x4B, 0x00, 0x00, 0x17, 0x04, 0xE1, 0x11,
		0x54, 0x15, 0xED, 0x88, 0x55, 0x21, 0x01, 0x33,
		0x00, 0x00, 0x80, 0x02, 0x5E, 0x04, 0x8E, 0x02,
		0x03, 0x00, 0x01, 0x01, 0xC1
	};

	unsigned char UsbdSecXSM3SetChallengeProtocolData[34] = {
		0x09, 0x40, 0x00, 0x00, 0x1C, 0x0A, 0x0F, 0x6B,
		0x0B, 0xA1, 0x18, 0x26, 0x5F, 0x83, 0x3C, 0x45,
		0x13, 0x49, 0x53, 0xBD, 0x18, 0x61, 0x73, 0xCF,
		0x29, 0xDE, 0x2C, 0xD8, 0x66, 0xE4, 0xAE, 0x34,
		0xA9, 0x9C
	};

	unsigned char UsbdSecXSM3GetResponseChallengeProtocolData[46] = {
		0x49, 0x4C, 0x00, 0x00, 0x28, 0x81, 0xBD, 0x7C,
		0xB3, 0x70, 0xBD, 0x76, 0x1A, 0x2F, 0x28, 0x6E,
		0xD1, 0xF2, 0xC3, 0x8E, 0xF9, 0x0B, 0xB2, 0x83,
		0x49, 0xCB, 0x4B, 0x24, 0xA2, 0x90, 0x6C, 0x27,
		0xB1, 0x05, 0x0A, 0xB0, 0x47, 0x09, 0x75, 0x16,
		0x07, 0xE1, 0xD7, 0xE8, 0xAF, 0x57
	};

	unsigned char UsbdSecXSM3SetVerifyProtocolData1[22] = {
		0x09, 0x41, 0x00, 0x00, 0x10, 0x5A, 0xDD, 0x1B,
		0xA0, 0x74, 0x87, 0xB7, 0x62, 0xB7, 0xA5, 0x8F,
		0x34, 0xFF, 0xE3, 0xD1, 0xD9, 0xA7
	};

	unsigned char UsbdSecXSM3GetResponseVerifyProtocolData1[22] = {
		0x49, 0x4C, 0x00, 0x00, 0x10, 0x5A, 0x9C, 0xD6,
		0x72, 0xB3, 0x70, 0x8D, 0xA7, 0x57, 0x01, 0x06,
		0x50, 0x20, 0x60, 0xA9, 0xBC, 0xDE
	};

	/* keys from key vault */

	unsigned char fixed_key_0x1D[16] = {
		0xE3, 0x5B, 0xFB, 0x1C, 0xCD, 0xAD, 0x32, 0x5B,
		0xF7, 0x0E, 0x07, 0xFD, 0x62, 0x3D, 0xA7, 0xC4
	};

	unsigned char fixed_key_0x1E[16] = {
		0x8F, 0x29, 0x08, 0x38, 0x0B, 0x5B, 0xFE, 0x68,
		0x7C, 0x26, 0x46, 0x2A, 0x51, 0xF2, 0xBC, 0x19
	};

	unsigned char kv_key_1[16] = {
		0xF1, 0x9D, 0x6F, 0x2C, 0xB1, 0xEE, 0x6A, 0xC4,
		0x63, 0x53, 0x36, 0xA5, 0x4C, 0x11, 0x00, 0x7D
	};

	unsigned char kv_key_2[16] = {
		0xC4, 0x55, 0x82, 0xC8, 0x9F, 0xC3, 0xDA, 0xD2,
		0x8C, 0x1F, 0xBB, 0xCF, 0x3D, 0x04, 0x9B, 0x6F
	};

	printf("UsbdSecXSM3GetIdentificationProtocolData\n");

	if (chksum(UsbdSecXSM3GetIdentificationProtocolData))
		return -1;

	UsbdSecGetIdentificationComplete(ProtocolData, UsbdSecXSM3GetIdentificationProtocolData);

	printf("UsbdSecXSM3AuthenticationChallenge\n");

	if (chksum(UsbdSecXSM3SetChallengeProtocolData))
		return -1;

	UsbdSecXSM3AuthenticationCrypt(fixed_key_0x1D, UsbdSecXSM3SetChallengeProtocolData + 5, 0x18, decrypted_data, 0);

	memcpy(Random, decrypted_data, 0x10);

	memcpy(Cert, decrypted_data + 0x10, 8);

	memcpy(mac_copy, UsbdSecXSM3SetChallengeProtocolData + 29, 4);

	UsbdSecXSM3AuthenticationCrypt(kv_key_1, Random, 0x10, RandomEnc, 1);

	*(unsigned long long *)RandomSwap = *(unsigned long long *)(Random + 8);
	*(unsigned long long *)(RandomSwap + 8) = *(unsigned long long *)Random;

	UsbdSecXSM3AuthenticationCrypt(kv_key_2, RandomSwap, 0x10, RandomSwapEnc, 1);

	UsbdSecXSM3AuthenticationMac(fixed_key_0x1E, 0, UsbdSecXSM3SetChallengeProtocolData + 5, 0x18, mac, 0);

	if (memcmp(mac_copy, mac + 4, 4))
	{
		printf("Mac is wrong!\n");
		return -1;
	}

	printf("UsbdSecXSM3GetResponseChallengeProtocolData\n");

	if (chksum(UsbdSecXSM3GetResponseChallengeProtocolData))
		return -1;

	UsbdSecXSM3AuthenticationCrypt(RandomEnc, UsbdSecXSM3GetResponseChallengeProtocolData + 5, 0x20, decrypted_data, 0);

	memcpy(UsbRandom, decrypted_data, 0x10);

	memcpy(random, decrypted_data + 0x10, 0x10);

	memcpy(acr_copy, UsbdSecXSM3GetResponseChallengeProtocolData + 37, 8);

	UsbdSecXSM3AuthenticationMac(RandomSwapEnc, 0, UsbdSecXSM3GetResponseChallengeProtocolData + 5, 0x20, mac, 1);
	
	UsbdSecXSMAuthenticationAcr(ProtocolData, mac, acr);

	if (memcmp(Random, random, 0x10))
	{
		printf("Random is wrong!\n");
		return -1;
	}
	
	if (memcmp(acr_copy, acr, 8))
	{
		printf("Acr is wrong!\n");
		return -1;
	}

	sha1(decrypted_data, 0x20, UsbCmdHash);

	*(unsigned int *)Random = *(unsigned int *)(UsbRandom + 0xC);
	*(unsigned int *)(Random + 4) = *(unsigned int *)(Random + 0xC);

	printf("UsbdSecXSM3SetVerifyProtocolData1\n");

	if (chksum(UsbdSecXSM3SetVerifyProtocolData1))
		return -1;

	UsbdSecXSM3AuthenticationCrypt(UsbRandom, UsbdSecXSM3SetVerifyProtocolData1 + 5, 8, decrypted_data, 0);

	*(unsigned long long *)(Random + 8) = *(unsigned long long *)decrypted_data;

	memcpy(mac_copy, UsbdSecXSM3SetVerifyProtocolData1 + 5 + 8, 8);

	UsbdSecXSM3AuthenticationMac(UsbCmdHash, Random, UsbdSecXSM3SetVerifyProtocolData1 + 5, 8, mac, 1);

	if (memcmp(mac_copy, mac, 8))
	{
		printf("Mac is wrong!\n");
		return -1;
	}

	printf("UsbdSecXSM3GetResponseVerifyProtocolData1\n");

	if (chksum(UsbdSecXSM3GetResponseVerifyProtocolData1))
		return -1;

	UsbdSecXSM3AuthenticationCrypt(RandomEnc, UsbdSecXSM3GetResponseVerifyProtocolData1 + 5, 8, decrypted_data, 0);

	memcpy(acr_copy, decrypted_data, 8);

	memcpy(mac_copy, UsbdSecXSM3GetResponseVerifyProtocolData1 + 5 + 8, 8);

	UsbdSecXSM3AuthenticationMac(RandomSwapEnc, Random, UsbdSecXSM3GetResponseVerifyProtocolData1 + 5, 8, mac, 1);

	UsbdSecXSMAuthenticationAcr(ProtocolData, Random + 8, acr);

	if (memcmp(mac_copy, mac, 8))
	{
		printf("Mac is wrong!\n");
		return -1;
	}
	
	if (memcmp(acr_copy, acr, 8))
	{
		printf("Acr is wrong!\n");
		return -1;
	}

	return result;
}

int main(int argc, char *argv[]) 
{
	printf("result = 0x%X\n", XSM3());

	return 0;
}
