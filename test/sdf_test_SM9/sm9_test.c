#include <sdf.h>
#include <sdf_type.h>
#include <sdf_dev_manage.h>
#include <sdf_sm9.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <malloc.h>

#define DUMP_DATA(d, l)\
do\
{\
	int i;\
	for(i=0;i<l;i++)\
	{\
		if((i+1) % 16) \
			printf("%02X ", d[i]);\
		else\
			printf("%02X\n", d[i]);\
	}\
	if(i % 16) printf("\n");\
}\
while(0)

int SDF_ExportSignMasterPublicKey_SM9(void *hSessionHandle, unsigned int uiMasterKeyindex, SM9SignMasterPublicKey *pSignMasterPubKey);
int EVDF_CreateSignMasterKeyPair_SM9(void *hSessionHandle, unsigned int uiAlgID, unsigned int uiMasterKeyindex, SM9SignMasterPublicKey *pPuclicKey);


int SM9_Genkey_Sign_Test(void *hSessionHandle)
{
		u32 r;
		SM9MasterPrivateKey prikey;
		SM9SignMasterPublicKey pubkey;
		SM9UserSignPrivateKey signvk;
		unsigned char M_in1[20] = "Chinese IBS standard"; 
		SM9Signature sigval;
				
		printf("%s()-start\n", __func__);
		
		r = SDF_GenerateSignMasterKeyPair_SM9(hSessionHandle, SGD_SM9_1, &prikey, &pubkey);
		if(r)
		{
			printf("SDF_GenerateSignMasterKeyPair_SM9 fail:%x\n", r);
			return r;
		}
		
		printf("gen sm9 sign master keypair\n");
		printf("sm9 prikey:\n");
		DUMP_DATA(prikey.s, 32);
		printf("sm9 pubkey:\n");
		DUMP_DATA(pubkey.xa, 32);
		DUMP_DATA(pubkey.xb, 32);
		DUMP_DATA(pubkey.ya, 32);
		DUMP_DATA(pubkey.yb, 32);
		
		
		r = EVDF_GenerateUserSignKey_SM9(hSessionHandle, SGD_SM9_1, &prikey, "Alice", 5, &signvk);
		if(r)
		{
			printf("EVDF_GenerateUserSignKey_SM9 fail:%x\n", r);
			return r;
		}
		
		printf("gen sm9 sign user keypair\n");
		printf("sm9 vk:\n");
		DUMP_DATA(signvk.x, 32);
		DUMP_DATA(signvk.y, 32);


		r = EVDF_SignWithMasterEPK_SM9(hSessionHandle, &pubkey, &signvk, M_in1, 20, &sigval);
		if(r)
		{
			printf("EVDF_SignWithMasterEPK_SM9 fail:%x\n", r);
			return r;
		}
	
		printf("sm9 user sign\n");
		printf("sm9 sign value:\n");
		DUMP_DATA(sigval.h, 32);
		DUMP_DATA(sigval.x, 32);
		DUMP_DATA(sigval.y, 32);

		r = SDF_VerifyWithMasterEPK_SM9(hSessionHandle, &pubkey, "Alice", 5, M_in1, 20, &sigval);
		if(r)
		{
			printf("SDF_VerifyWithMasterEPK_SM9 fail:%x\n", r);
			return r;
		}
		printf("sm9 user verify ok\n");
		
		printf("%s() - success\n", __func__);
		return 0;			
}

int SM9_Genkey_Enc_Test(void *hSessionHandle)
{
		u32 r;
		SM9MasterPrivateKey prikey;
		SM9EncMasterPublicKey pubkey;
		SM9UserEncPrivateKey encvk;	
		unsigned int declen;
		unsigned char data[32];
		unsigned char encdata[256];
		unsigned char decdata[256];
		SM9Cipher *psm9cipher = (SM9Cipher *)encdata;

		printf("%s()-start\n", __func__);
		
		r = SDF_GenerateEncMasterKeyPair_SM9(hSessionHandle, SGD_SM9_3, &prikey, &pubkey);
		if(r)
		{
			printf("SDF_GenerateSignMasterKeyPair_SM9 fail:%x\n", r);
			return r;
		}
		
		printf("gen sm9 Enc master keypair\n");
		printf("sm9 prikey:\n");
		DUMP_DATA(prikey.s, 32);
		printf("sm9 pubkey:\n");
		DUMP_DATA(pubkey.x, 32);
		DUMP_DATA(pubkey.y, 32);
				
		r = EVDF_GenerateUserEncKey_SM9(hSessionHandle, SGD_SM9_3, &prikey, "Bob", 3, &encvk);
		if(r)
		{
			printf("EVDF_GenerateUserEncKey_SM9 fail:%x\n", r);
			return r;
		}
		printf("gen sm9 enc user keypair\n");
		printf("sm9 vk:\n");
		DUMP_DATA(encvk.xa, 32);
		DUMP_DATA(encvk.xb, 32);
		DUMP_DATA(encvk.ya, 32);
		DUMP_DATA(encvk.yb, 32);

		memset(data, 0x12, 32);
		r = SDF_EncryptWithMasterEPK_SM9(hSessionHandle, &pubkey, "Bob", 3, SGD_SM9_8_ECB, NULL, data, 32, psm9cipher);
		if(r)
		{
			printf("SDF_EncryptWithMasterEPK_SM9 fail:%x\n", r);
			return r;
		}
		printf("sm9 encrypt with master keypair sm4\n");
		print_data("x:", psm9cipher->x, 32);
		print_data("y:", psm9cipher->y, 32);
		print_data("h:", psm9cipher->h, 32);
		printf("c[%d]:\n", psm9cipher->L);
		DUMP_DATA(psm9cipher->C, 32);

		declen = 256;
		r = EVDF_DecryptWithUserEncKey_SM9(hSessionHandle, &encvk, "Bob", 3, NULL, psm9cipher, decdata, &declen);
		if(r)
		{
			printf("EVDF_DecryptWithUserEncKey_SM9 fail:%x\n", r);
			return r;
		}
		printf("sm9 decrypt with user key sm4\n");
		print_data("decdata:", decdata, declen);


		memset(data, 0x13, 20);
		r = SDF_EncryptWithMasterEPK_SM9(hSessionHandle, &pubkey, "Bob", 3, SGD_SM9_SM3, NULL, data, 20, psm9cipher);
		if(r)
		{
			printf("SDF_EncryptWithMasterEPK_SM9 fail:%x\n", r);
			return r;
		}
		printf("sm9 encrypt with master keypair sm3\n");
		print_data("x:", psm9cipher->x, 32);
		print_data("y:", psm9cipher->y, 32);
		print_data("h:", psm9cipher->h, 32);
		printf("c[%d]:\n", psm9cipher->L);
		DUMP_DATA(psm9cipher->C, 20);		

		declen = 256;
		r = EVDF_DecryptWithUserEncKey_SM9(hSessionHandle, &encvk, "Bob", 3, NULL, psm9cipher, decdata, &declen);
		if(r)
		{
			printf("EVDF_DecryptWithUserEncKey_SM9 fail:%x\n", r);
			return r;
		}
		printf("sm9 decrypt with user key sm3\n");
		print_data("decdata:", decdata, declen);


		printf("%s() - success\n", __func__);
		return 0;
}


int SM9_Genkey_Encapkey_Test(void *hSessionHandle)
{
		u32 r;
		SM9MasterPrivateKey prikey;
		SM9EncMasterPublicKey pubkey;
		SM9UserEncPrivateKey encvk;
		SM9KeyPackage packey;
		void *hKey1;
		void *hKey2;
		unsigned char data[16];
		unsigned char encdata[16];
		unsigned char decdata[16];
		unsigned int datalen;
		unsigned int enclen;
		unsigned int declen;	
		int i;

				
		printf("%s()-start\n", __func__);
		
		r = SDF_GenerateEncMasterKeyPair_SM9(hSessionHandle, SGD_SM9_3, &prikey, &pubkey);
		if(r)
		{
			printf("SDF_GenerateSignMasterKeyPair_SM9 fail:%x\n", r);
			return r;
		}
		
		printf("gen sm9 Enc master keypair\n");
		printf("sm9 prikey:\n");
		DUMP_DATA(prikey.s, 32);
		printf("sm9 pubkey:\n");
		DUMP_DATA(pubkey.x, 32);
		DUMP_DATA(pubkey.y, 32);
				
		r = EVDF_GenerateUserEncKey_SM9(hSessionHandle, SGD_SM9_3, &prikey, "Bob", 3, &encvk);
		if(r)
		{
			printf("EVDF_GenerateUserEncKey_SM9 fail:%x\n", r);
			return r;
		}
		printf("gen sm9 enc user keypair\n");
		printf("sm9 vk:\n");
		DUMP_DATA(encvk.xa, 32);
		DUMP_DATA(encvk.xb, 32);
		DUMP_DATA(encvk.ya, 32);
		DUMP_DATA(encvk.yb, 32);	

		r = EVDF_GenerateKeyWithMasterEPK_SM9(hSessionHandle, 16, &pubkey, "Bob", 3, &packey, &hKey1);
		if(r)
		{
			printf("EVDF_GenerateKeyWithMasterEPK_SM9 fail:%x\n", r);
			return r;
		}
		printf("gen key with master epk\n");
		printf("sm9 packey:\n");
		DUMP_DATA(packey.x, 32);
		DUMP_DATA(packey.y, 32);

		r = EVDF_ImportKeyWithEncKey_SM9(hSessionHandle, 16, &encvk, "Bob", 3,  &packey, &hKey2);
		if(r)
		{
			printf("EVDF_ImportKeyWithEncKey_SM9 fail:%x\n", r);
			return r;
		}
		printf("import key with enc key\n");


		for(i=0; i<16; i++)
			data[i] = (unsigned char)(i);	
		datalen = 16;
	
		r = SDF_Encrypt(hSessionHandle, hKey1, SGD_SM1_ECB, NULL, data, datalen, encdata, &enclen);
		if(r)
		{
			printf("encrypt data fail:%x\n", r);
			return r;
		}
		print_data("encrypt data:", encdata, enclen);


		r = SDF_Decrypt(hSessionHandle, hKey2, SGD_SM1_ECB, NULL, encdata, enclen, decdata, &declen);
		if(r)
		{
			printf("decrypt data fail:%x\n", r);
			return r;		
		}
		print_data("decrypt data:", decdata, declen);


		if((declen != datalen) || memcmp(data, decdata, datalen))
		{
			printf("%s()-source data != dec data\n", __func__);
			return 1;
		}

		r = SDF_DestroyKey(hSessionHandle, hKey1);
		if(r)
		{
			printf("destroy session key1 fail:%x\n", r);
			return r;
		}

		r = SDF_DestroyKey(hSessionHandle, hKey2);
		if(r)
		{
			printf("destroy session key2 fail:%x\n", r);
			return r;
		}		

				
		printf("%s() - success\n", __func__);
		return 0;			
}

int SM9_Genkey_Exchange_Test(void *hSessionHandle)
{
		u32 r;
		SM9MasterPrivateKey prikey;
		SM9EncMasterPublicKey pubkey;
		SM9UserEncPrivateKey encvk1, encvk2;
		SM9EncMasterPublicKey tmppubkey1, tmppubkey2;
		void *hKey1;
		void *hKey2;
		void *hAgreement;
		unsigned char data[16];
		unsigned char encdata[16];
		unsigned char decdata[16];
		unsigned int datalen;
		unsigned int enclen;
		unsigned int declen;	
		int i;	
	
		
		printf("%s()-start\n", __func__);
		
		r = SDF_GenerateEncMasterKeyPair_SM9(hSessionHandle, SGD_SM9_2, &prikey, &pubkey);
		if(r)
		{
			printf("SDF_GenerateSignMasterKeyPair_SM9 fail:%x\n", r);
			return r;
		}	

		printf("gen sm9 Enc master keypair\n");
		printf("sm9 prikey:\n");
		DUMP_DATA(prikey.s, 32);
		printf("sm9 pubkey:\n");
		DUMP_DATA(pubkey.x, 32);
		DUMP_DATA(pubkey.y, 32);
				
		r = EVDF_GenerateUserEncKey_SM9(hSessionHandle, SGD_SM9_2, &prikey, "Alice", 5, &encvk1);
		if(r)
		{
			printf("EVDF_GenerateUserEncKey_SM9 fail:%x\n", r);
			return r;
		}
		printf("gen sm9 enc user keypair\n");
		printf("sm9 vk1:\n");
		DUMP_DATA(encvk1.xa, 32);
		DUMP_DATA(encvk1.xb, 32);
		DUMP_DATA(encvk1.ya, 32);
		DUMP_DATA(encvk1.yb, 32);	

		r = EVDF_GenerateUserEncKey_SM9(hSessionHandle, SGD_SM9_2, &prikey, "Bob", 3, &encvk2);
		if(r)
		{
			printf("EVDF_GenerateUserEncKey_SM9 fail:%x\n", r);
			return r;
		}
		printf("gen sm9 enc user keypair\n");
		printf("sm9 vk2:\n");
		DUMP_DATA(encvk2.xa, 32);
		DUMP_DATA(encvk2.xb, 32);
		DUMP_DATA(encvk2.ya, 32);
		DUMP_DATA(encvk2.yb, 32);

		r = EVDF_GenerateAgreementDataWithSM9(hSessionHandle, &pubkey, &encvk1, 128, "Bob", 3, "Alice", 5, &tmppubkey1, &hAgreement);
		if(r)
		{
			printf("EVDF_GenerateAgreementDataWithSM9 fail:%x\n", r);
			return r;
		}
		printf("step 1 A:\n");
		DUMP_DATA(tmppubkey1.x, 32);
		DUMP_DATA(tmppubkey1.y, 32);	
	
		r = EVDF_GenerateAgreementDataAndKeyWithSM9(hSessionHandle, &pubkey, &encvk2, 128, "Bob", 3, "Alice", 5, &tmppubkey1, &tmppubkey2, &hKey1);
		if(r)
		{
			printf("EVDF_GenerateAgreementDataAndKeyWithSM9 fail:%x\n", r);
			return r;
		}
		printf("step 2 B:\n");
		DUMP_DATA(tmppubkey2.x, 32);
		DUMP_DATA(tmppubkey2.y, 32);


		r = EVDF_GenerateKeyWithSM9(hSessionHandle, hAgreement, &tmppubkey2, &hKey2);
		if(r)
		{
			printf("EVDF_GenerateKeyWithSM9 fail:%x\n", r);
			return r;
		}	
		printf("step 3 A\n");	

		for(i=0; i<16; i++)
			data[i] = (unsigned char)(i);	
		datalen = 16;
	
		r = SDF_Encrypt(hSessionHandle, hKey1, SGD_SM1_ECB, NULL, data, datalen, encdata, &enclen);
		if(r)
		{
			printf("encrypt data fail:%x\n", r);
			return r;
		}
		print_data("encrypt data:", encdata, enclen);


		r = SDF_Decrypt(hSessionHandle, hKey2, SGD_SM1_ECB, NULL, encdata, enclen, decdata, &declen);
		if(r)
		{
			printf("decrypt data fail:%x\n", r);
			return r;		
		}
		print_data("decrypt data:", decdata, declen);


		if((declen != datalen) || memcmp(data, decdata, datalen))
		{
			printf("%s()-source data != dec data\n", __func__);
			return 1;
		}

		r = SDF_DestroyKey(hSessionHandle, hKey1);
		if(r)
		{
			printf("destroy session key1 fail:%x\n", r);
			return r;
		}

		r = SDF_DestroyKey(hSessionHandle, hKey2);
		if(r)
		{
			printf("destroy session key2 fail:%x\n", r);
			return r;
		}		

				
		printf("%s() - success\n", __func__);
		return 0;		

}

u32 SM9_Verify_Check(void *hSessionHandle)
{
		u32 r;
		SM9MasterPrivateKey prikey;
		SM9SignMasterPublicKey pubkey;
		SM9UserSignPrivateKey signvk;
		unsigned char M_in1[20] = "Chinese IBS standard"; 
		SM9Signature sigval;	
	
		unsigned char pubkey_data[128] = {0x79,0xe6,0x97,0xb5,0x8b,0xbc,0xe9,0xb3,0x41,0x95,0xc3,0x57,0xf2,0x95,0x35,0xc5,0x52,0x6a,0x27,0xd2,0xba,0xc9,0xd0,0x6f,0x70,0xfa,0xa3,0x6d,0x2b,0xe1,0xfc,0x5c,
																 			0x21,0x33,0xed,0x9d,0x13,0xd1,0x14,0x39,0x12,0x81,0xd7,0xb3,0xd6,0x20,0xbc,0x39,0x9c,0x61,0x02,0x15,0xe5,0xa8,0x49,0x3b,0xfc,0x4e,0xde,0xa3,0x3e,0xbc,0xab,0x40,
																 			0x5f,0x30,0x06,0x4d,0x72,0xf1,0x84,0x44,0x09,0x80,0x4b,0x16,0x91,0x99,0x67,0x0c,0x30,0xbc,0x2d,0xab,0x84,0x96,0x94,0xb8,0x01,0xa8,0x91,0x74,0x46,0xc7,0x61,0x4a,
																 			0x9d,0x24,0xf5,0x48,0x9f,0x52,0x39,0x3d,0xa5,0x0d,0xec,0x42,0x92,0x8e,0x92,0x60,0x05,0x38,0xf1,0x32,0x17,0x84,0xee,0x8e,0x1c,0x7f,0x33,0xb5,0xda,0x6e,0xe6,0xf0};
		unsigned char sig_s_data[64]  =  {0x45,0x12,0xf3,0xd6,0x86,0x46,0x76,0xf0,0x40,0x3a,0x43,0x88,0xe5,0x7d,0xb8,0x54,0xd2,0x33,0xfd,0x82,0x9f,0x72,0x44,0xec,0xeb,0x3d,0x83,0x2a,0xbe,0xd4,0xbd,0x90,
																 			0x41,0x7c,0x6e,0xc2,0x24,0xb5,0x13,0x0e,0x7e,0x34,0xc9,0x99,0x53,0x90,0x7c,0xf5,0x91,0xda,0xfa,0x16,0x16,0x3a,0x05,0xaa,0x54,0x55,0xcb,0xe0,0xe1,0x7d,0xfc,0xda};
		unsigned char sig_h_data[32] =   {0x72,0x6f,0xdb,0xf8,0x28,0x6c,0x2e,0x7f,0xea,0xd4,0x06,0x98,0x8b,0xff,0x20,0x54,0x32,0x36,0x56,0x71,0x3f,0x1c,0xbe,0x52,0x04,0xc2,0x69,0x01,0xf4,0xc6,0x4f,0xcf};
		unsigned char user_id_data[5] =  {0xe3,0x40,0x70,0x43,0x2b};
		unsigned char sig_plain_data[8] = {0x28,0x14,0x45,0x47,0x61,0x50,0x96,0x47};
	
		memcpy(pubkey.xa, &pubkey_data[0], 32);
		memcpy(pubkey.xb, &pubkey_data[32], 32);
		memcpy(pubkey.ya, &pubkey_data[64], 32);
		memcpy(pubkey.yb, &pubkey_data[96], 32);
		printf("sm9 pubkey:\n");
		DUMP_DATA(pubkey.xa, 32);
		DUMP_DATA(pubkey.xb, 32);
		DUMP_DATA(pubkey.ya, 32);
		DUMP_DATA(pubkey.yb, 32);	
	
		printf("sm9 user sign\n");
		memcpy(sigval.h, sig_h_data, 32);
		memcpy(sigval.x, &sig_s_data[0], 32);
		memcpy(sigval.y, &sig_s_data[32], 32);
		printf("sm9 sign value:\n");
		DUMP_DATA(sigval.h, 32);
		DUMP_DATA(sigval.x, 32);
		DUMP_DATA(sigval.y, 32);

		r = SDF_VerifyWithMasterEPK_SM9(hSessionHandle, &pubkey, user_id_data, 5, sig_plain_data, 8, &sigval);
		if(r)
		{
			printf("SDF_VerifyWithMasterEPK_SM9 fail:%x\n", r);
			return r;
		}
		printf("sm9 user verify ok\n");
		
		printf("%s() - success\n", __func__);
		return 0;	
}


u32 SM9_Dec_Symm_Check(void *hSessionHandle)
{
		u32 r;
		SM9MasterPrivateKey prikey;
		SM9EncMasterPublicKey pubkey;
		SM9UserEncPrivateKey encvk;	
		
		unsigned char prikey_data[128] = {0x71,0x34,0xbd,0x3b,0xb5,0x11,0x0d,0xcd,0x55,0x98,0xa9,0x89,0x78,0x7c,0x11,0xe2,
																	 0x51,0x77,0xe7,0x0d,0xa2,0xf5,0x04,0x50,0x48,0x47,0xdc,0x95,0x01,0x13,0xbf,0x72,
																	 0x8a,0xd9,0x96,0x32,0x0b,0x28,0xd4,0x70,0xa7,0xec,0x56,0x54,0xc5,0x14,0x22,0xbb,
																	 0x77,0x76,0x7b,0xdc,0x77,0x66,0x4d,0x12,0x61,0x09,0x6b,0x5d,0x7a,0xeb,0xc1,0x0e,
																	 0x64,0x77,0x28,0x0d,0xad,0x4a,0xf2,0x3a,0xc8,0x55,0xcd,0x4d,0x3b,0x9e,0xe6,0x48,
																	 0xef,0xe3,0xdd,0x5d,0x20,0x9f,0x65,0x01,0xb0,0xd0,0x2f,0x15,0x34,0x6d,0xeb,0xb2,
																	 0x8d,0xd2,0xd7,0xa8,0x46,0x1e,0x38,0x2b,0xf8,0xf7,0x56,0x52,0xbb,0xd5,0x36,0x7c,
																	 0x61,0xac,0xa7,0x42,0x63,0x8d,0x36,0xb6,0x2f,0x47,0x5c,0xd5,0xdf,0x90,0x5a,0x97}; 
		unsigned char user_id_data[5] = {0x2e,0xef,0xbc,0x71,0xb9};
		unsigned char cipher_data[112] = {0x44,0x9a,0xaa,0x75,0xc6,0x56,0xb4,0x6a,0x80,0xe1,0x9d,0x14,0x65,0x9d,0x63,0xd2,
																	 0x11,0x72,0x8a,0x6d,0x68,0x72,0x2a,0xb5,0x66,0xc4,0x61,0x22,0xb0,0x00,0x21,0xc2,
																	 0x1b,0x84,0x85,0x3f,0xe3,0x73,0xad,0x51,0xba,0xfb,0xa1,0xf6,0x30,0xf6,0x13,0xb3,
																	 0xc0,0x51,0xd5,0x06,0x8a,0xcc,0xd1,0xb8,0x00,0x01,0xcf,0xdb,0x02,0x89,0x3a,0x1a,
																	 0xda,0x28,0x0d,0xd7,0x1b,0xfc,0x9e,0x58,0x64,0xc9,0xb9,0x39,0xa9,0xcd,0xef,0xe9,
																	 0x47,0xdc,0x4c,0x31,0x6c,0xfc,0x07,0x9a,0x3b,0xb4,0x95,0x85,0x28,0x51,0xfd,0x18,
																	 0xdd,0xbc,0x13,0xe6,0xcf,0xda,0x85,0x51,0xa5,0x91,0x04,0x46,0xce,0xca,0x4a,0xe9};
		unsigned char plain_data[16] =  {0x42,0x72,0x65,0x5d,0x53,0xee,0x6d,0x8a,0x86,0x17,0xe4,0x21,0xd2,0x7d,0x95,0xf9};
		
		unsigned int declen;
		unsigned char data[32];
		unsigned char encdata[256];
		unsigned char decdata[256];
		SM9Cipher *psm9cipher = (SM9Cipher *)encdata;	
		
		memcpy(encvk.xa, &prikey_data[0], 32);
		memcpy(encvk.xb, &prikey_data[32], 32);
		memcpy(encvk.ya, &prikey_data[64], 32);
		memcpy(encvk.yb, &prikey_data[96], 32);
		printf("sm9 vk:\n");
		DUMP_DATA(encvk.xa, 32);
		DUMP_DATA(encvk.xb, 32);
		DUMP_DATA(encvk.ya, 32);
		DUMP_DATA(encvk.yb, 32);

		psm9cipher->enType = SGD_SM9_8_ECB;
		memcpy(psm9cipher->x, &cipher_data[0], 32);
		memcpy(psm9cipher->y, &cipher_data[32], 32);
		memcpy(psm9cipher->h, &cipher_data[64], 32);
		psm9cipher->L = 16;
		memcpy(psm9cipher->C, &cipher_data[96], 16);
		printf("sm9 encrypt with master keypair sm4\n");
		print_data("x:", psm9cipher->x, 32);
		print_data("y:", psm9cipher->y, 32);
		print_data("h:", psm9cipher->h, 32);
		printf("c[%d]:\n", psm9cipher->L);
		DUMP_DATA(psm9cipher->C, 16);	
		
		declen = 256;
		r = EVDF_DecryptWithUserEncKey_SM9(hSessionHandle, &encvk, user_id_data, 5, NULL, psm9cipher, decdata, &declen);
		if(r)
		{
			printf("EVDF_DecryptWithUserEncKey_SM9 fail:%x\n", r);
			return r;
		}
		printf("sm9 decrypt with user key sm4\n");
		print_data("decdata:", decdata, declen);		
		
		printf("%s() - success\n", __func__);
		return 0;			
}

u32 SM9_Decap_Check(void *hSessionHandle)
{
		u32 r;
		SM9MasterPrivateKey prikey;
		SM9EncMasterPublicKey pubkey;
		SM9UserEncPrivateKey encvk;
		SM9KeyPackage packey;
		void *hKey1;
		void *hKey2;
		unsigned char data[16];
		unsigned char encdata[16];
		unsigned char decdata[16];
		unsigned int datalen;
		unsigned int enclen;
		unsigned int declen;	
		int i;
		
		unsigned char privkey_data[128] = {0x82,0x01,0xa2,0x68,0xa5,0x64,0x10,0x8c,0x02,0xc7,0xbf,0x33,0x2c,0xf9,0x62,0xe6,
																		0x1b,0x0b,0x23,0x65,0xed,0x11,0x72,0x36,0xf8,0x9e,0xf3,0xfd,0x37,0xba,0x18,0x96,
																		0x84,0xd5,0x96,0xe2,0x45,0x9d,0x69,0x1b,0xb0,0x9b,0x58,0xa7,0xbb,0x62,0xe2,0xb9,
																		0x4b,0x55,0xe2,0x7f,0x0b,0x54,0x90,0x15,0x85,0x34,0x24,0x69,0xa2,0x2a,0x5e,0xd9,
																		0x74,0xec,0x6e,0xea,0xc4,0x21,0x85,0x66,0x43,0x61,0x78,0x01,0x21,0xff,0x15,0x23,
																		0xe0,0x55,0x7f,0xea,0x28,0x34,0x0c,0x60,0x67,0xe0,0xee,0x80,0xd6,0xdd,0xbc,0xad,
																		0x37,0x11,0x43,0x62,0x70,0xd8,0x10,0x20,0x44,0xc9,0xf8,0xbe,0xcd,0xde,0x77,0xba,
																		0x89,0xe9,0x0d,0x6a,0xc7,0x71,0xbd,0x9b,0x54,0xa9,0x97,0xff,0x49,0xc1,0xcf,0xf3};
		unsigned char user_id_data[3] = {0x4b,0xf0,0xbe};
		unsigned char packey_data[64] =  {0x63,0x98,0x90,0x91,0xa2,0xec,0xc1,0x5e,0x7e,0xa3,0x1b,0x25,0x15,0x94,0xc9,0x82,
																		0x26,0x83,0xdc,0x77,0x0a,0x80,0x8d,0xc7,0xc0,0xe4,0x4d,0x92,0xb7,0x9e,0x5d,0xf7,
																		0x96,0x59,0xfb,0x09,0xbd,0xb8,0x45,0x19,0xc2,0x3a,0x55,0xc2,0x64,0x18,0x5f,0xfa,
																		0xbc,0x63,0x30,0x8e,0x80,0xc7,0xf3,0xef,0xe0,0xf0,0x12,0xc2,0xb0,0x9f,0x19,0x57};
		unsigned char k_data[32] = 			 {0xdd,0xea,0x18,0xa3,0x3e,0xe3,0x85,0xce,0x74,0x6a,0x50,0x8e,0x85,0x8a,0x27,0xf6,
																		0x12,0xe9,0x63,0xf3,0xc7,0xa8,0xc6,0xd4,0x71,0xb2,0xd6,0x63,0xcd,0x1b,0x15,0x17};
		
		memcpy(encvk.xa, &privkey_data[0], 32);
		memcpy(encvk.xb, &privkey_data[32], 32);
		memcpy(encvk.ya, &privkey_data[64], 32);
		memcpy(encvk.yb, &privkey_data[96], 32);
		printf("sm9 vk:\n");
		DUMP_DATA(encvk.xa, 32);
		DUMP_DATA(encvk.xb, 32);
		DUMP_DATA(encvk.ya, 32);
		DUMP_DATA(encvk.yb, 32);
		
		printf("gen key with master epk\n");
		memcpy(packey.x, &packey_data[0], 32);
		memcpy(packey.y, &packey_data[32], 32);
		printf("sm9 packey:\n");
		DUMP_DATA(packey.x, 32);
		DUMP_DATA(packey.y, 32);

		r = EVDF_ImportKeyWithEncKey_SM9(hSessionHandle, 32, &encvk, user_id_data, 3,  &packey, &hKey2);
		if(r)
		{
			printf("EVDF_ImportKeyWithEncKey_SM9 fail:%x\n", r);
			return r;
		}
		printf("import key with enc key\n");	
		
		printf("%s() - success\n", __func__);
		return 0;				
}

u32 SM9_Exchange_Check(void *hSessionHandle)
{
	u32 r;
	SM9MasterPrivateKey prikey;
	SM9EncMasterPublicKey pubkey;
	SM9UserEncPrivateKey encvk1, encvk2;
	SM9EncMasterPublicKey tmppubkey1, tmppubkey2;
	void *hKey1;
	void *hKey2;
	void *hAgreement;
	
	unsigned char prikey_data[32] = 	 {0x00,0x02,0x37,0x5d,0x5a,0xdf,0xcc,0xe5,0x70,0xb5,0x25,0x54,0x18,0x54,0xe5,0xbf,
										 0x0e,0x96,0x77,0xf4,0x8c,0xb9,0x1c,0xc4,0x9c,0x72,0xa9,0xab,0xef,0xe0,0xc3,0xce};
	unsigned char user_id_a_data[5] = 	{0xac,0x27,0xb4,0x08,0xcb};
	unsigned char user_id_b_data[3] = 	{0x14,0x3f,0x16};
	unsigned char user_a_tmppubkey[64] = 	{0x26,0xd8,0xa3,0xa3,0x38,0xc7,0xa7,0x4f,0x64,0xbb,0x8d,0xfd,0x87,0x86,0x7a,0x80,
										 0xf5,0xfc,0x8c,0x9d,0x4a,0xe8,0x7c,0x86,0x60,0xdf,0x53,0xe2,0xa8,0xf5,0xc2,0x7d,
										 0x72,0x75,0x07,0x60,0x94,0xb7,0x88,0x50,0x72,0x26,0x75,0xee,0xa0,0xac,0x46,0x9e,
										 0xc9,0x4b,0x2c,0xf6,0xac,0x77,0x51,0x1a,0x5c,0x5c,0x92,0x4b,0xb7,0x5a,0xa7,0xa6};
	unsigned char user_a_privkey[32] =	{0x92,0xe8,0xf0,0xde,0xb5,0x66,0x95,0xfc,0x95,0xbc,0x2b,0x24,0x79,0x0e,0x8c,0xda,
										 0xfa,0xa7,0x5b,0x26,0x07,0x6f,0xde,0x42,0xcb,0xb9,0xe6,0x8e,0x10,0xf3,0x7c,0xac};
	unsigned char user_b_tmppubkey[64] = {0xab,0x8d,0x1e,0x73,0x00,0x8d,0x14,0xc3,0x22,0x8c,0xb8,0x46,0xe3,0xff,0x8b,0x22,
										 0x77,0xfa,0x18,0xab,0x1c,0x7b,0xc3,0x38,0xd4,0x58,0xd5,0x22,0x85,0xee,0x43,0xb4,
										 0x02,0xd6,0x61,0xd1,0x3f,0xc1,0x43,0xe7,0xfb,0x5e,0xcf,0xfb,0x2f,0xec,0x32,0x89,
										 0x4f,0x48,0x20,0x5f,0x97,0xec,0x27,0xd4,0x7e,0xd6,0x32,0x7f,0xe4,0x3e,0x6a,0xde};
	unsigned char user_b_privkey[32] = 	{0x4f,0xa5,0x20,0xd5,0xaa,0xc5,0x8b,0x24,0xd7,0xcd,0x33,0xb9,0xb3,0xf3,0x07,0x03,
										 0x01,0xb7,0xd9,0xc6,0x39,0x80,0x23,0x93,0x82,0xef,0x73,0x41,0xc1,0xfc,0x11,0x95};
	
	
	r = SDF_GenerateEncMasterKeyPair_SM9(hSessionHandle, SGD_SM9_2, &prikey, &pubkey);
	if(r)
	{
		printf("SDF_GenerateSignMasterKeyPair_SM9 fail:%x\n", r);
		return r;
	}	

	printf("gen sm9 Enc master keypair\n");
	printf("sm9 prikey:\n");
	DUMP_DATA(prikey.s, 32);
	printf("sm9 pubkey:\n");
	DUMP_DATA(pubkey.x, 32);
	DUMP_DATA(pubkey.y, 32);
				
	r = EVDF_GenerateUserEncKey_SM9(hSessionHandle, SGD_SM9_2, &prikey, user_id_a_data, 5, &encvk1);
	if(r)
	{
		printf("EVDF_GenerateUserEncKey_SM9 fail:%x\n", r);
		return r;
	}
	printf("gen sm9 enc user keypair\n");
	printf("sm9 vk1:\n");
	DUMP_DATA(encvk1.xa, 32);
	DUMP_DATA(encvk1.xb, 32);
	DUMP_DATA(encvk1.ya, 32);
	DUMP_DATA(encvk1.yb, 32);	

	r = EVDF_GenerateUserEncKey_SM9(hSessionHandle, SGD_SM9_2, &prikey, user_id_b_data, 3, &encvk2);
	if(r)
	{
		printf("EVDF_GenerateUserEncKey_SM9 fail:%x\n", r);
		return r;
	}
	printf("gen sm9 enc user keypair\n");
	printf("sm9 vk2:\n");
	DUMP_DATA(encvk2.xa, 32);
	DUMP_DATA(encvk2.xb, 32);
	DUMP_DATA(encvk2.ya, 32);
	DUMP_DATA(encvk2.yb, 32);
	
	r = EVDF_GenerateAgreementDataWithSM9(hSessionHandle, &pubkey, &encvk1, 128, user_id_b_data, 3, user_id_a_data, 5, &tmppubkey1, &hAgreement);
	if(r)
	{
		printf("EVDF_GenerateAgreementDataWithSM9 fail:%x\n", r);
		return r;
	}
	printf("step 1 A:\n");
	DUMP_DATA(tmppubkey1.x, 32);
	DUMP_DATA(tmppubkey1.y, 32);	

	r = EVDF_GenerateAgreementDataAndKeyWithSM9(hSessionHandle, &pubkey, &encvk2, 128, user_id_b_data, 3, user_id_a_data, 5, &tmppubkey1, &tmppubkey2, &hKey1);
	if(r)
	{
		printf("EVDF_GenerateAgreementDataAndKeyWithSM9 fail:%x\n", r);
		return r;
	}
	printf("step 2 B:\n");
	DUMP_DATA(tmppubkey2.x, 32);
	DUMP_DATA(tmppubkey2.y, 32);


	r = EVDF_GenerateKeyWithSM9(hSessionHandle, hAgreement, &tmppubkey2, &hKey2);
	if(r)
	{
		printf("EVDF_GenerateKeyWithSM9 fail:%x\n", r);
		return r;
	}	
	printf("step 3 A\n");	

	r = SDF_DestroyKey(hSessionHandle, hKey1);
	if(r)
	{
		printf("destroy session key1 fail:%x\n", r);
		return r;
	}

	r = SDF_DestroyKey(hSessionHandle, hKey2);
	if(r)
	{
		printf("destroy session key2 fail:%x\n", r);
		return r;
	}
	
	printf("%s() - success\n", __func__);
	return 0;	
}

u32 SM9_CreateSignMastKey_Test1(void *hSessionHandle)
{
	u32 r;
	SM9SignMasterPublicKey mast_pubkey_sign;
	SM9UserSignPrivateKey signvk;
	u32 mast_sign_key_index;
	u32 user_sign_key_index;
	unsigned char M_in1[20] = "Chinese IBS standard"; 
	SM9Signature sigval;	
	
#if 0	
	r = EVDF_InitKeyFileSystem(hSessionHandle, (char*)"11111111", NULL, 128, (char *)"11111111", (char *)"11111111");
	if(r)
	{
		printf("SDF_InitKeyFileSystem fail:%x\n", r);
		return r;
	}
	
	return 0;
	
#endif	
	
	r = SDF_GetPrivateKeyAccessRight(hSessionHandle, 0, "11111111", 8);//mast key stored in df0
	if(r)
	{
		printf("SDF_GetPrivateKeyAccessRight fail:%x\n", r);
		return r;
	}
	
	r = SDF_GetPrivateKeyAccessRight(hSessionHandle, 1, "11111111", 8);//user key stored in df1~df15
	if(r)
	{
		printf("SDF_GetPrivateKeyAccessRight fail:%x\n", r);
		return r;
	}
	
	mast_sign_key_index = 1;
#if 1	
	printf("gen sm9 sign master keypair\n");
	r = EVDF_CreateSignMasterKeyPair_SM9(hSessionHandle, SGD_SM9_1, mast_sign_key_index, &mast_pubkey_sign);
	if(r)
	{
		printf("EVDF_CreateSignMasterKeyPair_SM9 fail:%x\n", r);
		return r;
	}	
#endif	
	r = SDF_ExportSignMasterPublicKey_SM9(hSessionHandle, mast_sign_key_index, &mast_pubkey_sign);
	if(r)
	{
		printf("SDF_ExportSignMasterPublicKey_SM9 fail:%x\n", r);
		return r;
	}		
		
	printf("sm9 pubkey:\n");
	DUMP_DATA(mast_pubkey_sign.xa, 32);
	DUMP_DATA(mast_pubkey_sign.xb, 32);
	DUMP_DATA(mast_pubkey_sign.ya, 32);
	DUMP_DATA(mast_pubkey_sign.yb, 32);

#if 0
	r = SDF_GenerateUserSignKey_SM9(hSessionHandle, mast_sign_key_index, "Alice", 5, &signvk);
	if(r)
	{
		printf("SDF_GenerateUserSignKey_SM9 fail:%x\n", r);
		return r;
	}		


	printf("gen sm9 sign user keypair\n");
	printf("sm9 vk:\n");
	DUMP_DATA(signvk.x, 32);
	DUMP_DATA(signvk.y, 32);	
	
	r = EVDF_SignWithMasterEPK_SM9(hSessionHandle, &mast_pubkey_sign, &signvk, M_in1, 20, &sigval);
	if(r)
	{
		printf("EVDF_SignWithMasterEPK_SM9 fail:%x\n", r);
		return r;
	}

	printf("sm9 user sign\n");
	printf("sm9 sign value:\n");
	DUMP_DATA(sigval.h, 32);
	DUMP_DATA(sigval.x, 32);
	DUMP_DATA(sigval.y, 32);

	r = SDF_VerifyWithMasterEPK_SM9(hSessionHandle, &mast_pubkey_sign, "Alice", 5, M_in1, 20, &sigval);
	if(r)
	{
		printf("SDF_VerifyWithMasterEPK_SM9 fail:%x\n", r);
		return r;
	}
	printf("sm9 user verify ok\n");	
#else
	
	user_sign_key_index = 1;
	
	r = EVDF_CreateUserSignKey_SM9(hSessionHandle, SGD_SM9_1,mast_sign_key_index, user_sign_key_index, "Alice", 5);
	if(r)
	{
		printf("EVDF_CreateUserSignKey_SM9 fail:%x\n", r);
		return r;
	}	
	
	r = SDF_InternalSignWithMasterEPK_SM9(hSessionHandle, &mast_pubkey_sign, user_sign_key_index, M_in1, 20, &sigval);
	if(r)
	{
		printf("SDF_InternalSignWithMasterEPK_SM9 fail:%x\n", r);
		return r;
	}	
	
	printf("sm9 sign value1:\n");
	DUMP_DATA(sigval.h, 32);
	DUMP_DATA(sigval.x, 32);
	DUMP_DATA(sigval.y, 32);

	r = SDF_VerifyWithMasterEPK_SM9(hSessionHandle, &mast_pubkey_sign, "Alice", 5, M_in1, 20, &sigval);
	if(r)
	{
		printf("SDF_VerifyWithMasterEPK_SM9 fail:%x\n", r);
		return r;
	}
	printf("sm9 user verify ok\n");	
	
	
	r = SDF_InternalSignWithMasterIPK_SM9(hSessionHandle, mast_sign_key_index, user_sign_key_index, M_in1, 20, &sigval);
	if(r)
	{
		printf("SDF_InternalSignWithMasterIPK_SM9 fail:%x\n", r);
		return r;
	}	
	
	printf("sm9 sign value2:\n");
	DUMP_DATA(sigval.h, 32);
	DUMP_DATA(sigval.x, 32);
	DUMP_DATA(sigval.y, 32);
	
	r = SDF_VerifyWithMasterEPK_SM9(hSessionHandle, &mast_pubkey_sign, "Alice", 5, M_in1, 20, &sigval);
	if(r)
	{
		printf("SDF_VerifyWithMasterEPK_SM9 fail:%x\n", r);
		return r;
	}
	printf("sm9 user verify ok\n");		
	
	r = SDF_InternalSignWithMasterIPK_SM9(hSessionHandle, mast_sign_key_index, user_sign_key_index, M_in1, 20, &sigval);
	if(r)
	{
		printf("SDF_InternalSignWithMasterIPK_SM9 fail:%x\n", r);
		return r;
	}	
	
	printf("sm9 sign value3:\n");
	DUMP_DATA(sigval.h, 32);
	DUMP_DATA(sigval.x, 32);
	DUMP_DATA(sigval.y, 32);	
	
	r = SDF_VerifyWithMasterIPK_SM9(hSessionHandle, mast_sign_key_index, "Alice", 5, M_in1, 20, &sigval);
	if(r)
	{
		printf("SDF_VerifyWithMasterIPK_SM9 fail:%x\n", r);
		return r;
	}
	printf("sm9 user verify ok\n");		
	
	r = EVDF_DeleteInternalKeyPair_SM9(hSessionHandle, 0, 1, user_sign_key_index, "11111111");
	if(r)
	{
		printf("EVDF_DeleteInternalKeyPair_SM9 userkey fail:%x\n", r);
		return r;
	}
	
	r = EVDF_DeleteInternalKeyPair_SM9(hSessionHandle, 1, 1, mast_sign_key_index, "11111111");
	if(r)
	{
		printf("EVDF_DeleteInternalKeyPair_SM9 mastkey fail:%x\n", r);
		return r;
	}
#endif		
	printf("%s() - success\n", __func__);
	return 0;	
}


u32 SM9_CreateSignMastKey_Test2(void *hSessionHandle)
{
	u32 r;
	SM9SignMasterPublicKey mast_pubkey_sign;
	SM9UserSignPrivateKey signvk;
	u32 mast_sign_key_index;
	u32 user_sign_key_index;
	unsigned char M_in1[20] = "Chinese IBS standard"; 
	SM9Signature sigval;	
	
#if 0	
	r = EVDF_InitKeyFileSystem(hSessionHandle, (char*)"11111111", NULL, 128, (char *)"11111111", (char *)"11111111");
	if(r)
	{
		printf("SDF_InitKeyFileSystem fail:%x\n", r);
		return r;
	}
	
	return 0;
	
#endif	
	
	r = SDF_GetPrivateKeyAccessRight(hSessionHandle, 0, "11111111", 8);//mast key stored in df0
	if(r)
	{
		printf("SDF_GetPrivateKeyAccessRight fail:%x\n", r);
		return r;
	}
	
	r = SDF_GetPrivateKeyAccessRight(hSessionHandle, 1, "11111111", 8);//user key stored in df1~df15
	if(r)
	{
		printf("SDF_GetPrivateKeyAccessRight fail:%x\n", r);
		return r;
	}
	
	mast_sign_key_index = 1;
	
	printf("gen sm9 sign master keypair\n");
	
	// r = EVDF_CreateSignMasterKeyPair_SM9(hSessionHandle, SGD_SM9_1, mast_sign_key_index, &mast_pubkey_sign);
	// if(r)
	// {
		// printf("EVDF_CreateSignMasterKeyPair_SM9 fail:%x\n", r);
		// return r;
	// }	

	r = SDF_ExportSignMasterPublicKey_SM9(hSessionHandle, mast_sign_key_index, &mast_pubkey_sign);
	if(r)
	{
		printf("SDF_ExportSignMasterPublicKey_SM9 fail:%x\n", r);
		return r;
	}		
		
	printf("sm9 pubkey:\n");
	DUMP_DATA(mast_pubkey_sign.xa, 32);
	DUMP_DATA(mast_pubkey_sign.xb, 32);
	DUMP_DATA(mast_pubkey_sign.ya, 32);
	DUMP_DATA(mast_pubkey_sign.yb, 32);


#if 0
	r = SDF_GenerateUserSignKey_SM9(hSessionHandle, mast_sign_key_index, "Alice", 5, &signvk);
	if(r)
	{
		printf("SDF_GenerateUserSignKey_SM9 fail:%x\n", r);
		return r;
	}		


	printf("gen sm9 sign user keypair\n");
	printf("sm9 vk:\n");
	DUMP_DATA(signvk.x, 32);
	DUMP_DATA(signvk.y, 32);	
	
	r = EVDF_SignWithMasterEPK_SM9(hSessionHandle, &mast_pubkey_sign, &signvk, M_in1, 20, &sigval);
	if(r)
	{
		printf("EVDF_SignWithMasterEPK_SM9 fail:%x\n", r);
		return r;
	}

	printf("sm9 user sign\n");
	printf("sm9 sign value:\n");
	DUMP_DATA(sigval.h, 32);
	DUMP_DATA(sigval.x, 32);
	DUMP_DATA(sigval.y, 32);

	r = SDF_VerifyWithMasterEPK_SM9(hSessionHandle, &mast_pubkey_sign, "Alice", 5, M_in1, 20, &sigval);
	if(r)
	{
		printf("SDF_VerifyWithMasterEPK_SM9 fail:%x\n", r);
		return r;
	}
	printf("sm9 user verify ok\n");	
#else
	
	user_sign_key_index = 1;
	
	 r = EVDF_CreateUserSignKey_SM9(hSessionHandle, SGD_SM9_1,mast_sign_key_index, user_sign_key_index, "Alice", 5);
	 if(r)
	 {
		 printf("EVDF_CreateUserSignKey_SM9 fail:%x\n", r);
		 return r;
	 }	
	
	r = SDF_InternalSignWithMasterEPK_SM9(hSessionHandle, &mast_pubkey_sign, user_sign_key_index, M_in1, 20, &sigval);
	if(r)
	{
		printf("SDF_InternalSignWithMasterEPK_SM9 fail:%x\n", r);
		return r;
	}	
	
	printf("sm9 sign value1:\n");
	DUMP_DATA(sigval.h, 32);
	DUMP_DATA(sigval.x, 32);
	DUMP_DATA(sigval.y, 32);

	r = SDF_VerifyWithMasterEPK_SM9(hSessionHandle, &mast_pubkey_sign, "Alice", 5, M_in1, 20, &sigval);
	if(r)
	{
		printf("SDF_VerifyWithMasterEPK_SM9 fail:%x\n", r);
		return r;
	}
	printf("sm9 user verify ok\n");	
	
	
	r = SDF_InternalSignWithMasterIPK_SM9(hSessionHandle, mast_sign_key_index, user_sign_key_index, M_in1, 20, &sigval);
	if(r)
	{
		printf("SDF_InternalSignWithMasterIPK_SM9 fail:%x\n", r);
		return r;
	}	
	
	printf("sm9 sign value2:\n");
	DUMP_DATA(sigval.h, 32);
	DUMP_DATA(sigval.x, 32);
	DUMP_DATA(sigval.y, 32);
	
	r = SDF_VerifyWithMasterEPK_SM9(hSessionHandle, &mast_pubkey_sign, "Alice", 5, M_in1, 20, &sigval);
	if(r)
	{
		printf("SDF_VerifyWithMasterEPK_SM9 fail:%x\n", r);
		return r;
	}
	printf("sm9 user verify ok\n");		
	
	r = SDF_InternalSignWithMasterIPK_SM9(hSessionHandle, mast_sign_key_index, user_sign_key_index, M_in1, 20, &sigval);
	if(r)
	{
		printf("SDF_InternalSignWithMasterIPK_SM9 fail:%x\n", r);
		return r;
	}	
	
	printf("sm9 sign value3:\n");
	DUMP_DATA(sigval.h, 32);
	DUMP_DATA(sigval.x, 32);
	DUMP_DATA(sigval.y, 32);	
	
	r = SDF_VerifyWithMasterIPK_SM9(hSessionHandle, mast_sign_key_index, "Alice", 5, M_in1, 20, &sigval);
	if(r)
	{
		printf("SDF_VerifyWithMasterIPK_SM9 fail:%x\n", r);
		return r;
	}
	printf("sm9 user verify ok\n");		
	
	 r = EVDF_DeleteInternalKeyPair_SM9(hSessionHandle, 0, 1, user_sign_key_index, "11111111");
	 if(r)
	 {
		 printf("EVDF_DeleteInternalKeyPair_SM9 userkey fail:%x\n", r);
		 return r;
	 }
#endif	
	
	 r = EVDF_DeleteInternalKeyPair_SM9(hSessionHandle, 1, 1, mast_sign_key_index, "11111111");
	 if(r)
	 {
		 printf("EVDF_DeleteInternalKeyPair_SM9 mastkey fail:%x\n", r);
		 return r;
	 }
	
	printf("%s() - success\n", __func__);
	return 0;	
}


u32 SM9_CreateEncMastKey_Test1(void *hSessionHandle)
{
		u32 r;
		SM9EncMasterPublicKey pubkey;
		SM9UserEncPrivateKey encvk;	
		u32 mast_enc_key_index;
		u32 user_enc_key_index;
		unsigned int declen;
		unsigned char data[32];
		unsigned char encdata[256];
		unsigned char decdata[256];
		SM9Cipher *psm9cipher = (SM9Cipher *)encdata;		
#if 0		
		r = EVDF_InitKeyFileSystem(hSessionHandle, (char*)"11111111", NULL, 128, (char *)"11111111", (char *)"11111111");
		if(r)
		{
			printf("SDF_InitKeyFileSystem fail:%x\n", r);
			return r;
		}
#endif
	
		r = SDF_GetPrivateKeyAccessRight(hSessionHandle, 0, "11111111", 8);//mast key stored in df0
		if(r)
		{
			printf("SDF_GetPrivateKeyAccessRight fail:%x\n", r);
			return r;
		}

		r = SDF_GetPrivateKeyAccessRight(hSessionHandle, 1, "11111111", 8);//user key stored in df1~df15
		if(r)
		{
			printf("SDF_GetPrivateKeyAccessRight fail:%x\n", r);
			return r;
		}
	
		mast_enc_key_index = 1;	
		
		 r = EVDF_CreateEncMasterKeyPair_SM9(hSessionHandle, SGD_SM9_3, mast_enc_key_index, &pubkey);
		 if(r)
		 {
			 printf("EVDF_CreateEncMasterKeyPair_SM9 fail:%x\n", r);
			 return r;
		 }
		
		r = SDF_ExportEncMasterPublicKey_SM9(hSessionHandle, mast_enc_key_index, &pubkey);
		if(r)
		{
			printf("SDF_ExportEncMasterPublicKey_SM9 fail:%x\n", r);
			return r;
		}	
		
		printf("gen sm9 Enc master keypair\n");
		printf("sm9 pubkey:\n");
		DUMP_DATA(pubkey.x, 32);
		DUMP_DATA(pubkey.y, 32);

#if 1		
		r = SDF_GenerateUserEncKey_SM9(hSessionHandle, mast_enc_key_index, "Bob", 3, &encvk);
		if(r)
		{
			printf("SDF_ExportEncMasterPublicKey_SM9 fail:%x\n", r);
			return r;
		}			
		
		printf("gen sm9 enc user keypair\n");
		printf("sm9 vk:\n");
		DUMP_DATA(encvk.xa, 32);
		DUMP_DATA(encvk.xb, 32);
		DUMP_DATA(encvk.ya, 32);
		DUMP_DATA(encvk.yb, 32);		
		
		memset(data, 0x12, 32);
		r = SDF_EncryptWithMasterEPK_SM9(hSessionHandle, &pubkey, "Bob", 3, SGD_SM9_8_ECB, NULL, data, 32, psm9cipher);
		if(r)
		{
			printf("SDF_EncryptWithMasterEPK_SM9 fail:%x\n", r);
			return r;
		}
		printf("sm9 encrypt with master keypair sm4\n");
		print_data("x:", psm9cipher->x, 32);
		print_data("y:", psm9cipher->y, 32);
		print_data("h:", psm9cipher->h, 32);
		printf("c[%d]:\n", psm9cipher->L);
		DUMP_DATA(psm9cipher->C, 32);
		
		declen = 256;
		r = EVDF_DecryptWithUserEncKey_SM9(hSessionHandle, &encvk, "Bob", 3, NULL, psm9cipher, decdata, &declen);
		if(r)
		{
			printf("EVDF_DecryptWithUserEncKey_SM9 fail:%x\n", r);
			return r;
		}
		printf("sm9 decrypt with user key sm4\n");
		print_data("decdata:", decdata, declen);

#else
		
		user_enc_key_index = 1;
		
		r = EVDF_CreateUserEncKey_SM9(hSessionHandle, SGD_SM9_3, mast_enc_key_index, user_enc_key_index, "Bob", 3);
		if(r)
		{
			printf("EVDF_CreateUserEncKey_SM9 fail:%x\n", r);
			return r;
		}	
				
		memset(data, 0x12, 32);
		r = SDF_EncryptWithMasterEPK_SM9(hSessionHandle, &pubkey, "Bob", 3, SGD_SM9_8_ECB, NULL, data, 32, psm9cipher);
		if(r)
		{
			printf("SDF_EncryptWithMasterEPK_SM9 fail:%x\n", r);
			return r;
		}
		printf("sm9 encrypt with master keypair sm4-1\n");
		print_data("x:", psm9cipher->x, 32);
		print_data("y:", psm9cipher->y, 32);
		print_data("h:", psm9cipher->h, 32);
		printf("c[%d]:\n", psm9cipher->L);
		DUMP_DATA(psm9cipher->C, 32);
		
		
		declen = 256;
		r = SDF_DecryptWithInternalKey_SM9(hSessionHandle, user_enc_key_index, NULL, psm9cipher, decdata, &declen);
		if(r)
		{
			printf("SDF_DecryptWithInternalKey_SM9 fail:%x\n", r);
			return r;
		}
		printf("sm9 decrypt with user key sm4-1\n");
		print_data("decdata:", decdata, declen);
		
	
		memset(data, 0x12, 32);
		r = SDF_EncryptWithMasterIPK_SM9(hSessionHandle, mast_enc_key_index, "Bob", 3, SGD_SM9_8_ECB, NULL, data, 32, psm9cipher);
		if(r)
		{
			printf("SDF_EncryptWithMasterIPK_SM9 fail:%x\n", r);
			return r;
		}		
		printf("sm9 encrypt with master keypair sm4-2\n");
		print_data("x:", psm9cipher->x, 32);
		print_data("y:", psm9cipher->y, 32);
		print_data("h:", psm9cipher->h, 32);
		printf("c[%d]:\n", psm9cipher->L);
		DUMP_DATA(psm9cipher->C, 32);

		declen = 256;
		r = SDF_DecryptWithInternalKey_SM9(hSessionHandle, user_enc_key_index, NULL, psm9cipher, decdata, &declen);
		if(r)
		{
			printf("SDF_DecryptWithInternalKey_SM9 fail:%x\n", r);
			return r;
		}
		printf("sm9 decrypt with user key sm4-2\n");
		print_data("decdata:", decdata, declen);		
		
		r = EVDF_DeleteInternalKeyPair_SM9(hSessionHandle, 0, 0, user_enc_key_index, "11111111");
		if(r)
		{
			printf("EVDF_DeleteInternalKeyPair_SM9 mastkey fail:%x\n", r);
			return r;
		}

#endif
		
		// r = EVDF_DeleteInternalKeyPair_SM9(hSessionHandle, 1, 0, mast_enc_key_index, "11111111");
		// if(r)
		// {
			// printf("EVDF_DeleteInternalKeyPair_SM9 mastkey fail:%x\n", r);
			// return r;
		// }
		
		printf("%s() - success\n", __func__);
		return 0;				
}


u32 SM9_CreateEncMastKey_Test2(void *hSessionHandle)
{
		u32 r;
		SM9EncMasterPublicKey pubkey;
		SM9UserEncPrivateKey encvk;	
		u32 mast_enc_key_index;
		u32 user_enc_key_index;
		unsigned int declen;
		unsigned char data[32];
		unsigned char encdata[256];
		unsigned char decdata[256];
		SM9Cipher *psm9cipher = (SM9Cipher *)encdata;		
#if 0		
		r = EVDF_InitKeyFileSystem(hSessionHandle, (char*)"11111111", NULL, 128, (char *)"11111111", (char *)"11111111");
		if(r)
		{
			printf("SDF_InitKeyFileSystem fail:%x\n", r);
			return r;
		}
#endif
	
		r = SDF_GetPrivateKeyAccessRight(hSessionHandle, 0, "11111111", 8);//mast key stored in df0
		if(r)
		{
			printf("SDF_GetPrivateKeyAccessRight fail:%x\n", r);
			return r;
		}

		r = SDF_GetPrivateKeyAccessRight(hSessionHandle, 1, "11111111", 8);//user key stored in df1~df15
		if(r)
		{
			printf("SDF_GetPrivateKeyAccessRight fail:%x\n", r);
			return r;
		}
	
		mast_enc_key_index = 1;	
		
		// r = EVDF_CreateEncMasterKeyPair_SM9(hSessionHandle, SGD_SM9_3, mast_enc_key_index, &pubkey);
		// if(r)
		// {
			// printf("EVDF_CreateEncMasterKeyPair_SM9 fail:%x\n", r);
			// return r;
		// }
		
		r = SDF_ExportEncMasterPublicKey_SM9(hSessionHandle, mast_enc_key_index, &pubkey);
		if(r)
		{
			printf("SDF_ExportEncMasterPublicKey_SM9 fail:%x\n", r);
			return r;
		}	
		
		printf("gen sm9 Enc master keypair\n");
		printf("sm9 pubkey:\n");
		DUMP_DATA(pubkey.x, 32);
		DUMP_DATA(pubkey.y, 32);

#if 0		
		r = SDF_GenerateUserEncKey_SM9(hSessionHandle, mast_enc_key_index, "Bob", 3, &encvk);
		if(r)
		{
			printf("SDF_ExportEncMasterPublicKey_SM9 fail:%x\n", r);
			return r;
		}			
		
		printf("gen sm9 enc user keypair\n");
		printf("sm9 vk:\n");
		DUMP_DATA(encvk.xa, 32);
		DUMP_DATA(encvk.xb, 32);
		DUMP_DATA(encvk.ya, 32);
		DUMP_DATA(encvk.yb, 32);		
		
		memset(data, 0x12, 32);
		r = SDF_EncryptWithMasterEPK_SM9(hSessionHandle, &pubkey, "Bob", 3, SGD_SM9_8_ECB, NULL, data, 32, psm9cipher);
		if(r)
		{
			printf("SDF_EncryptWithMasterEPK_SM9 fail:%x\n", r);
			return r;
		}
		printf("sm9 encrypt with master keypair sm4\n");
		print_data("x:", psm9cipher->x, 32);
		print_data("y:", psm9cipher->y, 32);
		print_data("h:", psm9cipher->h, 32);
		printf("c[%d]:\n", psm9cipher->L);
		DUMP_DATA(psm9cipher->C, 32);
		
		declen = 256;
		r = EVDF_DecryptWithUserEncKey_SM9(hSessionHandle, &encvk, "Bob", 3, NULL, psm9cipher, decdata, &declen);
		if(r)
		{
			printf("EVDF_DecryptWithUserEncKey_SM9 fail:%x\n", r);
			return r;
		}
		printf("sm9 decrypt with user key sm4\n");
		print_data("decdata:", decdata, declen);

#else
		
		user_enc_key_index = 1;
		
		 r = EVDF_CreateUserEncKey_SM9(hSessionHandle, SGD_SM9_3, mast_enc_key_index, user_enc_key_index, "Bob", 3);
		 if(r)
		 {
			 printf("EVDF_CreateUserEncKey_SM9 fail:%x\n", r);
			 return r;
		 }	
				
		memset(data, 0x12, 32);
		r = SDF_EncryptWithMasterEPK_SM9(hSessionHandle, &pubkey, "Bob", 3, SGD_SM9_8_ECB, NULL, data, 32, psm9cipher);
		if(r)
		{
			printf("SDF_EncryptWithMasterEPK_SM9 fail:%x\n", r);
			return r;
		}
		printf("sm9 encrypt with master keypair sm4-1\n");
		print_data("x:", psm9cipher->x, 32);
		print_data("y:", psm9cipher->y, 32);
		print_data("h:", psm9cipher->h, 32);
		printf("c[%d]:\n", psm9cipher->L);
		DUMP_DATA(psm9cipher->C, 32);
		
		
		declen = 256;
		r = SDF_DecryptWithInternalKey_SM9(hSessionHandle, user_enc_key_index, NULL, psm9cipher, decdata, &declen);
		if(r)
		{
			printf("SDF_DecryptWithInternalKey_SM9 fail:%x\n", r);
			return r;
		}
		printf("sm9 decrypt with user key sm4-1\n");
		print_data("decdata:", decdata, declen);
		
	
		memset(data, 0x12, 32);
		r = SDF_EncryptWithMasterIPK_SM9(hSessionHandle, mast_enc_key_index, "Bob", 3, SGD_SM9_8_ECB, NULL, data, 32, psm9cipher);
		if(r)
		{
			printf("SDF_EncryptWithMasterIPK_SM9 fail:%x\n", r);
			return r;
		}		
		printf("sm9 encrypt with master keypair sm4-2\n");
		print_data("x:", psm9cipher->x, 32);
		print_data("y:", psm9cipher->y, 32);
		print_data("h:", psm9cipher->h, 32);
		printf("c[%d]:\n", psm9cipher->L);
		DUMP_DATA(psm9cipher->C, 32);

		declen = 256;
		r = SDF_DecryptWithInternalKey_SM9(hSessionHandle, user_enc_key_index, NULL, psm9cipher, decdata, &declen);
		if(r)
		{
			printf("SDF_DecryptWithInternalKey_SM9 fail:%x\n", r);
			return r;
		}
		printf("sm9 decrypt with user key sm4-2\n");
		print_data("decdata:", decdata, declen);		
		
		// r = EVDF_DeleteInternalKeyPair_SM9(hSessionHandle, 0, 0, user_enc_key_index, "11111111");
		// if(r)
		// {
			// printf("EVDF_DeleteInternalKeyPair_SM9 mastkey fail:%x\n", r);
			// return r;
		// }

#endif
		
		// r = EVDF_DeleteInternalKeyPair_SM9(hSessionHandle, 1, 0, mast_enc_key_index, "11111111");
		// if(r)
		// {
			// printf("EVDF_DeleteInternalKeyPair_SM9 mastkey fail:%x\n", r);
			// return r;
		// }
		
		printf("%s() - success\n", __func__);
		return 0;				
}


u32 SM9_CreateEncMastKey_Test3(void *hSessionHandle)
{
		u32 r;
		SM9EncMasterPublicKey pubkey;
		SM9UserEncPrivateKey encvk;	
		u32 mast_enc_key_index;
		u32 user_enc_key_index;
		SM9KeyPackage packey;
		void *hKey1;
		void *hKey2;
		unsigned char data[16];
		unsigned char encdata[16];
		unsigned char decdata[16];
		unsigned int datalen;
		unsigned int enclen;
		unsigned int declen;	
		int i;		
		
		r = SDF_GetPrivateKeyAccessRight(hSessionHandle, 0, "11111111", 8);//mast key stored in df0
		if(r)
		{
			printf("SDF_GetPrivateKeyAccessRight fail:%x\n", r);
			return r;
		}

		r = SDF_GetPrivateKeyAccessRight(hSessionHandle, 1, "11111111", 8);//user key stored in df1~df15
		if(r)
		{
			printf("SDF_GetPrivateKeyAccessRight fail:%x\n", r);
			return r;
		}
	
		mast_enc_key_index = 1;	
		
		// r = EVDF_CreateEncMasterKeyPair_SM9(hSessionHandle, SGD_SM9_3, mast_enc_key_index, &pubkey);
		// if(r)
		// {
			// printf("EVDF_CreateEncMasterKeyPair_SM9 fail:%x\n", r);
			// return r;
		// }
		
		r = SDF_ExportEncMasterPublicKey_SM9(hSessionHandle, mast_enc_key_index, &pubkey);
		if(r)
		{
			printf("SDF_ExportEncMasterPublicKey_SM9 fail:%x\n", r);
			return r;
		}	
		
		printf("gen sm9 Enc master keypair\n");
		printf("sm9 pubkey:\n");
		DUMP_DATA(pubkey.x, 32);
		DUMP_DATA(pubkey.y, 32);

		user_enc_key_index = 1;
		
		// r = EVDF_CreateUserEncKey_SM9(hSessionHandle, SGD_SM9_3, mast_enc_key_index, user_enc_key_index, "Bob", 3);
		// if(r)
		// {
			// printf("EVDF_CreateUserEncKey_SM9 fail:%x\n", r);
			// return r;
		// }

#if 0
		r = SDF_GenerateKeyWithMasterEPK_SM9(hSessionHandle, 16, &pubkey, "Bob", 3, &packey, &hKey1);
		if(r)
		{
			printf("SDF_GenerateKeyWithMasterEPK_SM9 fail:%x\n", r);
			return r;
		}
#else
		r = SDF_GenerateKeyWithMasterIPK_SM9(hSessionHandle, 16, mast_enc_key_index, "Bob", 3, &packey, &hKey1);
		if(r)
		{
			printf("SDF_GenerateKeyWithMasterIPK_SM9 fail:%x\n", r);
			return r;
		}
#endif	
		printf("gen key with master epk\n");
		printf("sm9 packey:\n");
		DUMP_DATA(packey.x, 32);
		DUMP_DATA(packey.y, 32);

		r = SDF_ImportKeyWithISK_SM9(hSessionHandle, user_enc_key_index, 16, &packey, &hKey2);
		if(r)
		{
			printf("SDF_ImportKeyWithISK_SM9 fail:%x\n", r);
			return r;
		}
		printf("import key with enc key\n");


		for(i=0; i<16; i++)
			data[i] = (unsigned char)(i);	
		datalen = 16;
	
		r = SDF_Encrypt(hSessionHandle, hKey1, SGD_SM1_ECB, NULL, data, datalen, encdata, &enclen);
		if(r)
		{
			printf("encrypt data fail:%x\n", r);
			return r;
		}
		print_data("encrypt data:", encdata, enclen);


		r = SDF_Decrypt(hSessionHandle, hKey2, SGD_SM1_ECB, NULL, encdata, enclen, decdata, &declen);
		if(r)
		{
			printf("decrypt data fail:%x\n", r);
			return r;		
		}
		print_data("decrypt data:", decdata, declen);


		if((declen != datalen) || memcmp(data, decdata, datalen))
		{
			printf("%s()-source data != dec data\n", __func__);
			return 1;
		}

		r = SDF_DestroyKey(hSessionHandle, hKey1);
		if(r)
		{
			printf("destroy session key1 fail:%x\n", r);
			return r;
		}

		r = SDF_DestroyKey(hSessionHandle, hKey2);
		if(r)
		{
			printf("destroy session key2 fail:%x\n", r);
			return r;
		}


		// r = EVDF_DeleteInternalKeyPair_SM9(hSessionHandle, 0, 0, user_enc_key_index, "11111111");
		// if(r)
		// {
			// printf("EVDF_DeleteInternalKeyPair_SM9 mastkey fail:%x\n", r);
			// return r;
		// }


		// r = EVDF_DeleteInternalKeyPair_SM9(hSessionHandle, 1, 0, mast_enc_key_index, "11111111");
		// if(r)
		// {
			// printf("EVDF_DeleteInternalKeyPair_SM9 mastkey fail:%x\n", r);
			// return r;
		// }
		
		printf("%s() - success\n", __func__);
		return 0;			
}



u32 SM9_CreateEncMastKey_Test4(void *hSessionHandle)
{
		u32 r;
		SM9EncMasterPublicKey pubkey;
		SM9UserEncPrivateKey encvk;	
		u32 mast_enc_key_index;
		u32 user_enc_key_index;
		SM9KeyPackage packey;
		void *hKey1;
		void *hKey2;
		unsigned char data[16];
		unsigned char encdata[16];
		unsigned char decdata[16];
		unsigned int datalen;
		unsigned int enclen;
		unsigned int declen;	
		int i;		
		
		r = SDF_GetPrivateKeyAccessRight(hSessionHandle, 0, "11111111", 8);//mast key stored in df0
		if(r)
		{
			printf("SDF_GetPrivateKeyAccessRight fail:%x\n", r);
			return r;
		}

		r = SDF_GetPrivateKeyAccessRight(hSessionHandle, 1, "11111111", 8);//user key stored in df1~df15
		if(r)
		{
			printf("SDF_GetPrivateKeyAccessRight fail:%x\n", r);
			return r;
		}
	
		mast_enc_key_index = 1;	
		
		// r = EVDF_CreateEncMasterKeyPair_SM9(hSessionHandle, SGD_SM9_3, mast_enc_key_index, &pubkey);
		// if(r)
		// {
			// printf("EVDF_CreateEncMasterKeyPair_SM9 fail:%x\n", r);
			// return r;
		// }
		
		r = SDF_ExportEncMasterPublicKey_SM9(hSessionHandle, mast_enc_key_index, &pubkey);
		if(r)
		{
			printf("SDF_ExportEncMasterPublicKey_SM9 fail:%x\n", r);
			return r;
		}	
		
		printf("gen sm9 Enc master keypair\n");
		printf("sm9 pubkey:\n");
		DUMP_DATA(pubkey.x, 32);
		DUMP_DATA(pubkey.y, 32);

		user_enc_key_index = 1;
		
		// r = EVDF_CreateUserEncKey_SM9(hSessionHandle, SGD_SM9_3, mast_enc_key_index, user_enc_key_index, "Bob", 3);
		// if(r)
		// {
			// printf("EVDF_CreateUserEncKey_SM9 fail:%x\n", r);
			// return r;
		// }

#if 1
		r = SDF_GenerateKeyWithMasterEPK_SM9(hSessionHandle, 16, &pubkey, "Bob", 3, &packey, &hKey1);
		if(r)
		{
			printf("SDF_GenerateKeyWithMasterEPK_SM9 fail:%x\n", r);
			return r;
		}
#else
		r = SDF_GenerateKeyWithMasterIPK_SM9(hSessionHandle, 16, mast_enc_key_index, "Bob", 3, &packey, &hKey1);
		if(r)
		{
			printf("SDF_GenerateKeyWithMasterIPK_SM9 fail:%x\n", r);
			return r;
		}
#endif	
		printf("gen key with master epk\n");
		printf("sm9 packey:\n");
		DUMP_DATA(packey.x, 32);
		DUMP_DATA(packey.y, 32);

		r = SDF_ImportKeyWithISK_SM9(hSessionHandle, user_enc_key_index, 16, &packey, &hKey2);
		if(r)
		{
			printf("SDF_ImportKeyWithISK_SM9 fail:%x\n", r);
			return r;
		}
		printf("import key with enc key\n");


		for(i=0; i<16; i++)
			data[i] = (unsigned char)(i);	
		datalen = 16;
	
		r = SDF_Encrypt(hSessionHandle, hKey1, SGD_SM1_ECB, NULL, data, datalen, encdata, &enclen);
		if(r)
		{
			printf("encrypt data fail:%x\n", r);
			return r;
		}
		print_data("encrypt data:", encdata, enclen);


		r = SDF_Decrypt(hSessionHandle, hKey2, SGD_SM1_ECB, NULL, encdata, enclen, decdata, &declen);
		if(r)
		{
			printf("decrypt data fail:%x\n", r);
			return r;		
		}
		print_data("decrypt data:", decdata, declen);


		if((declen != datalen) || memcmp(data, decdata, datalen))
		{
			printf("%s()-source data != dec data\n", __func__);
			return 1;
		}

		r = SDF_DestroyKey(hSessionHandle, hKey1);
		if(r)
		{
			printf("destroy session key1 fail:%x\n", r);
			return r;
		}

		r = SDF_DestroyKey(hSessionHandle, hKey2);
		if(r)
		{
			printf("destroy session key2 fail:%x\n", r);
			return r;
		}


		// r = EVDF_DeleteInternalKeyPair_SM9(hSessionHandle, 0, 0, user_enc_key_index, "11111111");
		// if(r)
		// {
			// printf("EVDF_DeleteInternalKeyPair_SM9 mastkey fail:%x\n", r);
			// return r;
		// }


		// r = EVDF_DeleteInternalKeyPair_SM9(hSessionHandle, 1, 0, mast_enc_key_index, "11111111");
		// if(r)
		// {
			// printf("EVDF_DeleteInternalKeyPair_SM9 mastkey fail:%x\n", r);
			// return r;
		// }
		
		printf("%s() - success\n", __func__);
		return 0;			
}


u32 SM9_CreateEncMastKey_Test5(void *hSessionHandle)
{
	u32 r;
	SM9EncMasterPublicKey pubkey;
	SM9UserEncPrivateKey encvk;	
	u32 mast_enc_key_index_1;
	u32 mast_enc_key_index_2;
	u32 user_enc_key_index_1;
	u32 user_enc_key_index_2;
	SM9EncMasterPublicKey tmppubkey1, tmppubkey2;
	void *hKey1;
	void *hKey2;
	void *hAgreement;
	unsigned char data[16];
	unsigned char encdata[16];
	unsigned char decdata[16];
	unsigned int datalen;
	unsigned int enclen;
	unsigned int declen;	
	int i;		

	r = SDF_GetPrivateKeyAccessRight(hSessionHandle, 0, "11111111", 8);//mast key stored in df0
	if(r)
	{
		printf("SDF_GetPrivateKeyAccessRight fail:%x\n", r);
		return r;
	}

	r = SDF_GetPrivateKeyAccessRight(hSessionHandle, 5, "11111111", 8);//user key stored in df1~df15
	if(r)
	{
		printf("SDF_GetPrivateKeyAccessRight fail:%x\n", r);
		return r;
	}

	r = SDF_GetPrivateKeyAccessRight(hSessionHandle, 6, "11111111", 8);//user key stored in df1~df15
	if(r)
	{
		printf("SDF_GetPrivateKeyAccessRight fail:%x\n", r);
		return r;
	}

	r = SDF_GetPrivateKeyAccessRight(hSessionHandle, 7, "11111111", 8);//user key stored in df1~df15
	if(r)
	{
		printf("SDF_GetPrivateKeyAccessRight fail:%x\n", r);
		return r;
	}

	mast_enc_key_index_1 = 5;
	mast_enc_key_index_2 = 7;			

	r = EVDF_CreateEncMasterKeyPair_SM9(hSessionHandle, SGD_SM9_2, mast_enc_key_index_1, &pubkey);
	if(r) {
		if(r == 0x100001a) {
			r = SDF_ExportEncMasterPublicKey_SM9(hSessionHandle, mast_enc_key_index_1, &pubkey);
			if(r)
			{
				printf("SDF_ExportEncMasterPublicKey_SM9 fail:%x\n", r);
				return r;
			}	
		} else {
			printf("EVDF_CreateEncMasterKeyPair_SM9 fail:%x\n", r);
			return r;
		}
	}

	printf("gen sm9 Enc master keypair\n");
	printf("sm9 pubkey:\n");
	DUMP_DATA(pubkey.x, 32);
	DUMP_DATA(pubkey.y, 32);

	user_enc_key_index_1 = 6;
	user_enc_key_index_2 = 7;

	r = EVDF_CreateUserEncKey_SM9(hSessionHandle, SGD_SM9_2, mast_enc_key_index_1, user_enc_key_index_1, "Alice", 5);
	if(r)
	{
		if(r != 0x100001a) {
			printf("EVDF_CreateUserEncKey_SM9 fail:%x\n", r);
			return r;
		}
	}

	r = EVDF_CreateUserEncKey_SM9(hSessionHandle, SGD_SM9_2, mast_enc_key_index_1, user_enc_key_index_2, "Bob", 3);
	if(r)
	{
		if(r != 0x100001a) {
			printf("EVDF_CreateUserEncKey_SM9 fail:%x\n", r);
			return r;
		}
	}

	r = SDF_GenerateAgreementDataWithSM9(hSessionHandle, mast_enc_key_index_1, user_enc_key_index_1, 128, "Bob", 3, "Alice", 5, &tmppubkey1, &hAgreement);
	if(r)
	{
		printf("SDF_GenerateAgreementDataWithSM9 fail:%x\n", r);
		return r;
	}
	printf("step 1 A:\n");
	DUMP_DATA(tmppubkey1.x, 32);
	DUMP_DATA(tmppubkey1.y, 32);	

	r = SDF_GenerateAgreementDataAndKeyWithSM9(hSessionHandle, mast_enc_key_index_1, user_enc_key_index_2, 128, "Bob", 3, "Alice", 5, &tmppubkey1, &tmppubkey2, &hKey1);
	if(r)
	{
		printf("SDF_GenerateAgreementDataAndKeyWithSM9 fail:%x\n", r);
		return r;
	}
	printf("step 2 B:\n");
	DUMP_DATA(tmppubkey2.x, 32);
	DUMP_DATA(tmppubkey2.y, 32);

	r = SDF_GenerateKeyWithSM9(hSessionHandle, hAgreement, &tmppubkey2, &hKey2);
	if(r)
	{
		printf("SDF_GenerateKeyWithSM9 fail:%x\n", r);
		return r;
	}	
	printf("step 3 A\n");


	for(i=0; i<16; i++)
		data[i] = (unsigned char)(i);	
	datalen = 16;

	r = SDF_Encrypt(hSessionHandle, hKey1, SGD_SM1_ECB, NULL, data, datalen, encdata, &enclen);
	if(r)
	{
		printf("encrypt data fail:%x\n", r);
		return r;
	}
	print_data("encrypt data:", encdata, enclen, 16);


	r = SDF_Decrypt(hSessionHandle, hKey2, SGD_SM1_ECB, NULL, encdata, enclen, decdata, &declen);
	if(r)
	{
		printf("decrypt data fail:%x\n", r);
		return r;		
	}
	print_data("decrypt data:", decdata, declen, 16);


	if((declen != datalen) || memcmp(data, decdata, datalen))
	{
		printf("%s()-source data != dec data\n", __func__);
		return 1;
	}

	r = SDF_DestroyKey(hSessionHandle, hKey1);
	if(r)
	{
		printf("destroy session key1 fail:%x\n", r);
		return r;
	}

	r = SDF_DestroyKey(hSessionHandle, hKey2);
	if(r)
	{
		printf("destroy session key2 fail:%x\n", r);
		return r;
	}


	// r = EVDF_DeleteInternalKeyPair_SM9(hSessionHandle, 0, 0, user_enc_key_index_1, "11111111");
	// if(r)
	// {
	// printf("EVDF_DeleteInternalKeyPair_SM9 mastkey fail:%x\n", r);
	// return r;
	// }

	// r = EVDF_DeleteInternalKeyPair_SM9(hSessionHandle, 0, 0, user_enc_key_index_2, "11111111");
	// if(r)
	// {
	// printf("EVDF_DeleteInternalKeyPair_SM9 mastkey fail:%x\n", r);
	// return r;
	// }

	// r = EVDF_DeleteInternalKeyPair_SM9(hSessionHandle, 1, 0, mast_enc_key_index, "11111111");
	// if(r)
	// {
	// printf("EVDF_DeleteInternalKeyPair_SM9 mastkey fail:%x\n", r);
	// return r;
	// }

	printf("%s() - success\n", __func__);
	return 0;			
}

u32 SM9_ImportFile_Test1(void *hSessionHandle)
{
	u32 r;
	int gen_user_sign_key_index;
	int import_user_sign_key_index;
	int encrypt_user_sign_enc_key_index;
	SM9EncMasterPublicKey ecnrypt_mast_pubkey;
	SM9PairSignEnvelopedKey user_sign_evk;
	unsigned char M_in1[20] = "Chinese IBS standard"; 
	SM9Signature sigval;	

	r = SDF_GetPrivateKeyAccessRight(hSessionHandle, 0, "11111111", 8);//mast key stored in df0
	if(r)
	{
		printf("SDF_GetPrivateKeyAccessRight fail:%x\n", r);
		return r;
	}
	
	r = SDF_GetPrivateKeyAccessRight(hSessionHandle, 1, "11111111", 8);//mast key stored in df0
	if(r)
	{
		printf("SDF_GetPrivateKeyAccessRight fail:%x\n", r);
		return r;
	}
	
	r = SDF_GetPrivateKeyAccessRight(hSessionHandle, 2, "11111111", 8);//mast key stored in df0
	if(r)
	{
		printf("SDF_GetPrivateKeyAccessRight fail:%x\n", r);
		return r;
	}
	
	r = SDF_GetPrivateKeyAccessRight(hSessionHandle, 8, "11111111", 8);//mast key stored in df0
	if(r)
	{
		printf("SDF_GetPrivateKeyAccessRight fail:%x\n", r);
		return r;
	}
	
	gen_user_sign_key_index = 1;
	encrypt_user_sign_enc_key_index = 2;
	import_user_sign_key_index = 8;
	
 	r = SDF_ExportEncMasterPublicKey_SM9(hSessionHandle, encrypt_user_sign_enc_key_index, &ecnrypt_mast_pubkey);
 	if(r)
 	{
 		printf("SDF_ExportEncMasterPublicKey_SM9 fail:%x\n", r);
 		return r;
 	}	
 	
 	printf("sm9 enc mast pubkey:\n");
 	DUMP_DATA(ecnrypt_mast_pubkey.x, 32);
 	DUMP_DATA(ecnrypt_mast_pubkey.y, 32); 
 	
 	r = SDF_GenerateUserSignKeyWithMasterEPK_SM9(hSessionHandle, gen_user_sign_key_index, "Alice", 5, "Bob", 3, &ecnrypt_mast_pubkey, &user_sign_evk);
 	if(r)
 	{
 		printf("SDF_GenerateUserSignKeyWithMasterEPK_SM9 fail:%x\n", r);
 		return r;
 	}

	printf("20230811import_user_sign_key_index :%d\n", import_user_sign_key_index);

 	r = SDF_ImportUserSignKeyWithMasterISK_SM9(hSessionHandle, encrypt_user_sign_enc_key_index, &user_sign_evk, &import_user_sign_key_index);
 	if(r)
 	{
 		printf("SDF_ImportUserSignKeyWithMasterISK_SM9 fail:%x\n", r);
 		return r;
 	}

	printf("20230811import_user_sign_key_index :%d\n", import_user_sign_key_index);

	r = SDF_InternalSignWithMasterIPK_SM9(hSessionHandle, gen_user_sign_key_index, import_user_sign_key_index, M_in1, 20, &sigval);
	if(r)
	{
		printf("SDF_InternalSignWithMasterIPK_SM9 fail:%x\n", r);
		return r;
	}	
	
	printf("sm9 sign value2:\n");
	DUMP_DATA(sigval.h, 32);
	DUMP_DATA(sigval.x, 32);
	DUMP_DATA(sigval.y, 32);
	
	r = SDF_VerifyWithMasterIPK_SM9(hSessionHandle, gen_user_sign_key_index, "Alice", 5, M_in1, 20, &sigval);
	if(r)
	{
		printf("SDF_VerifyWithMasterIPK_SM9 fail:%x\n", r);
		//return r;
	}
	printf("sm9 user verify ok\n");		
	
	
	r = EVDF_DeleteInternalKeyPair_SM9(hSessionHandle, 0, 1, import_user_sign_key_index, "11111111");
	if(r)
	{
		printf("EVDF_DeleteInternalKeyPair_SM9 mastkey fail:%x\n", r);
		return r;
	}	
	
	printf("%s() - success\n", __func__);
	return 0;	
}



u32 SM9_ImportFile_Test2(void *hSessionHandle)
{
	u32 r;
	int gen_user_enc_key_index;
	int import_user_enc_key_index;
	int encrypt_user_enc_enc_key_index;
	SM9EncMasterPublicKey ecnrypt_mast_pubkey;
	SM9PairEncEnvelopedKey user_enc_evk;
	unsigned int declen;
	unsigned char data[32];
	unsigned char encdata[256];
	unsigned char decdata[256];
	SM9Cipher *psm9cipher = (SM9Cipher *)encdata;	
	
	
	r = SDF_GetPrivateKeyAccessRight(hSessionHandle, 0, "11111111", 8);//mast key stored in df0
	if(r)
	{
		printf("SDF_GetPrivateKeyAccessRight fail:%x\n", r);
		return r;
	}
	
	r = SDF_GetPrivateKeyAccessRight(hSessionHandle, 1, "11111111", 8);//mast key stored in df0
	if(r)
	{
		printf("SDF_GetPrivateKeyAccessRight fail:%x\n", r);
		return r;
	}
	
	r = SDF_GetPrivateKeyAccessRight(hSessionHandle, 2, "11111111", 8);//mast key stored in df0
	if(r)
	{
		printf("SDF_GetPrivateKeyAccessRight fail:%x\n", r);
		return r;
	}
	
	r = SDF_GetPrivateKeyAccessRight(hSessionHandle, 9, "11111111", 8);//mast key stored in df0
	if(r)
	{
		printf("SDF_GetPrivateKeyAccessRight fail:%x\n", r);
		return r;
	}
	
	gen_user_enc_key_index = 1;
	encrypt_user_enc_enc_key_index = 2;
	import_user_enc_key_index = 9;
	
	r = SDF_ExportEncMasterPublicKey_SM9(hSessionHandle, encrypt_user_enc_enc_key_index, &ecnrypt_mast_pubkey);
	if(r)
	{
		printf("SDF_ExportEncMasterPublicKey_SM9 fail:%x\n", r);
		return r;
	}	
	
	printf("sm9 enc mast pubkey:\n");
	DUMP_DATA(ecnrypt_mast_pubkey.x, 32);
	DUMP_DATA(ecnrypt_mast_pubkey.y, 32); 
	
	r = SDF_GenerateUserEncKeyWithMasterEPK_SM9(hSessionHandle, gen_user_enc_key_index, "Alice", 5, "Bob", 3, &ecnrypt_mast_pubkey, &user_enc_evk);
	if(r)
	{
		printf("SDF_GenerateUserEncKeyWithMasterEPK_SM9 fail:%x\n", r);
		return r;
	}
	
	r = SDF_ImportUserEncKeyWithMasterISK_SM9(hSessionHandle, encrypt_user_enc_enc_key_index, &user_enc_evk, &import_user_enc_key_index);
	if(r)
	{
		printf("SDF_ImportUserEncKeyWithMasterISK_SM9 fail:%x\n", r);
		return r;
	}


	memset(data, 0x12, 32);
	r = SDF_EncryptWithMasterIPK_SM9(hSessionHandle, gen_user_enc_key_index, "Alice", 5, SGD_SM9_8_ECB, NULL, data, 32, psm9cipher);
	if(r)
	{
		printf("SDF_EncryptWithMasterIPK_SM9 fail:%x\n", r);
		return r;
	}		
	printf("sm9 encrypt with master keypair sm4-2\n");
	print_data("x:", psm9cipher->x, 32);
	print_data("y:", psm9cipher->y, 32);
	print_data("h:", psm9cipher->h, 32);
	printf("c[%d]:\n", psm9cipher->L);
	DUMP_DATA(psm9cipher->C, 32);

	declen = 256;
	r = SDF_DecryptWithInternalKey_SM9(hSessionHandle, import_user_enc_key_index, NULL, psm9cipher, decdata, &declen);
	if(r)
	{
		printf("SDF_DecryptWithInternalKey_SM9 fail:%x\n", r);
		return r;
	}
	printf("sm9 decrypt with user key sm4-2\n");
	print_data("decdata:", decdata, declen);		
	
	r = EVDF_DeleteInternalKeyPair_SM9(hSessionHandle, 0, 0, import_user_enc_key_index, "11111111");
	if(r)
	{
		printf("EVDF_DeleteInternalKeyPair_SM9 mastkey fail:%x\n", r);
		return r;
	}

	
	printf("%s() - success\n", __func__);
	return 0;	
}



u32 SM9_CreateFile(void *hSessionHandle)
{
	u32 r;
	int i;
	SM9SignMasterPublicKey pubkey_sign;
	SM9EncMasterPublicKey pubkey_enc;
	
	for(i=0; i<10; i++)
	{
		r = SDF_GetPrivateKeyAccessRight(hSessionHandle, i, "11111111", 8);//mast key stored in df0
		if(r)
		{
			printf("SDF_GetPrivateKeyAccessRight fail:%x\n", r);
			return r;
		}
	}		
	
	
	printf("create sign keypair\n");
	//1~4
	for(i=1; i<5; i++) 
	{
		r = EVDF_CreateSignMasterKeyPair_SM9(hSessionHandle, SGD_SM9_1, i, &pubkey_sign);
		if(r)
		{
			printf("EVDF_CreateSignMasterKeyPair_SM9 fail:%x\n", r);
			return r;
		}
		
 		r = EVDF_CreateUserSignKey_SM9(hSessionHandle, SGD_SM9_1, i, i, "Alice", 5);
 		if(r)
 		{
 			printf("EVDF_CreateUserSignKey_SM9 fail:%x\n", r);
 			return r;
 		}
		
	}
	
	printf("create enc keypair\n");
	//1~4
	for(i=1; i<5; i++) 
	{
		r = EVDF_CreateEncMasterKeyPair_SM9(hSessionHandle, SGD_SM9_3, i, &pubkey_enc);
		if(r)
		{
			printf("EVDF_CreateEncMasterKeyPair_SM9 fail:%x\n", r);
			return r;
		}
		
 		r = EVDF_CreateUserEncKey_SM9(hSessionHandle, SGD_SM9_3, i, i, "Bob", 3);
 		if(r)
 		{
 			printf("EVDF_CreateUserEncKey_SM9 fail:%x\n", r);
 			return r;
 		}
		
	}
	
//	printf("create exch keypair\n");
	
	//6~9
	//for(i=6; i<10; i++) 
// 	{
// 		r = EVDF_CreateEncMasterKeyPair_SM9(hSessionHandle, SGD_SM9_2, 5, &pubkey_enc);
// 		if(r)
// 		{
// 			printf("EVDF_CreateEncMasterKeyPair_SM9 fail:%x\n", r);
// 			return r;
// 		}
// 		
// 			
// 		r = EVDF_CreateUserEncKey_SM9(hSessionHandle, SGD_SM9_2, 5, 6, "Alice", 5);
// 		if(r)
// 		{
// 			printf("EVDF_CreateUserEncKey_SM9 fail:%x\n", r);
// 			return r;
// 		}
// 			
// 		r = EVDF_CreateUserEncKey_SM9(hSessionHandle, SGD_SM9_2, 5, 7, "Bob", 3);		
// 		if(r)
// 		{
// 			printf("EVDF_CreateUserEncKey_SM9 fail:%x\n", r);
// 			return r;
// 		}
// 		
// 	}

	printf("%s() - success\n", __func__);
	return 0;	
}

u32 SM9_Performance_Test(void)
{
	
	thread_test_sm9_genkey_performance(SGD_SM9, 1000);
	thread_test_sm9_ext_sign_verify_performance(SGD_SM9, 100);
	thread_test_sm9_ext_enc_dec_performance(SGD_SM9_8_ECB, 100, 32);
	thread_test_sm9_ext_enc_dec_performance(SGD_SM9_SM3, 100, 32);
	
	return 0;
}


u32 SM9_Test(void *hSessionHandle)
{
	u32 i;
	u32 r;
		

 	r = SM9_Performance_Test();
 	
 	return r;
	
//    	r = SM9_CreateFile(hSessionHandle);
//    	if(r)
//    	{
//    			return r;
//    	}
    // 	r = SM9_ImportFile_Test1(hSessionHandle);
  	// if(r)
  	// {
  	// 	return r;
  	// }
// 	r = SM9_ImportFile_Test2(hSessionHandle);
// 	if(r)
// 	{
// 		return r;
// 	}
  
	
		
	// for(i=0; i<0x1000; i++)
	{		

		//printf("%s : test loop : %d\n", __func__, i);
		
//  		r = SM9_Genkey_Sign_Test(hSessionHandle);
//  		if(r)
//  		{
//  				return r;
//  		}
//  		
//  		r = SM9_Genkey_Enc_Test(hSessionHandle);
//  		if(r)
//  		{
//  				return r;
//  		}
//  		
//  		r = SM9_Genkey_Encapkey_Test(hSessionHandle);
//  		if(r)
//  		{
//  				return r;
//  		}
//  		
//  		r = SM9_Verify_Check(hSessionHandle);
//  		if(r)
//  		{
//  				return r;
//  		}
//  		
//  		r = SM9_Dec_Symm_Check(hSessionHandle);
//  		if(r)
//  		{
//  				return r;
//  		}
//  		
//  		r = SM9_Genkey_Exchange_Test(hSessionHandle);
//  		if(r)
//  		{
//  				return r;
//  		}
//  		
//  		
//    		r = SM9_CreateSignMastKey_Test1(hSessionHandle);
//    		if(r)
//    		{
//    				return r;
//    		}
//  		
//    		r = SM9_CreateSignMastKey_Test2(hSessionHandle);
//    		if(r)
//    		{
//    				return r;
//    		}
//   		
//   		r = SM9_CreateEncMastKey_Test1(hSessionHandle);
//   		if(r)
//   		{
//   				return r;
//   		}
//   		
//   		r = SM9_CreateEncMastKey_Test2(hSessionHandle);
//   		if(r)
//   		{
//   				return r;
//   		}
//   		
//   		r = SM9_CreateEncMastKey_Test3(hSessionHandle);
//   		if(r)
//   		{
//   				return r;
//   		}
//   		
//   		r = SM9_CreateEncMastKey_Test4(hSessionHandle);
//   		if(r)
//   		{
//   				return r;
//   		}
 		
//   		r = SM9_CreateEncMastKey_Test5(hSessionHandle);
//   		if(r)
//   		{
//   				return r;
//   		}
// 		 r = SM9_Decap_Check(hSessionHandle);
// 		 if(r)
// 		 {
// 				 return r;
// 		 }	
		
	}	
	
	return 0;
}