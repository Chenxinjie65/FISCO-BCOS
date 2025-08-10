#include <sdf.h>
#include <sdf_type.h>
#include <sdf_dev_manage.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <malloc.h>
#include "rsa_2048_key.h"
#include "rsa_2048_data.h"
#include "symm_data.h"
#include "hash_data.h"
#include "asymm_data.h"
#include "pert.h"



 //#define INIT_KEY
// 
// #define INFO
// #define RAND
// //#define RANDFILE
// #define KEY_ACCESS
#define SM9
// #define ECC
// #define RSA
// #define RSA1024
// #define ECC_CALC
// #define RSA_CALC
// #define ECC_EXTKEY
// #define ECC_INTKEY
// #define RSA_EXTKEY
// #define ECC_SESSKEY
// #define RSA_SESSKEY
// #define ECC_DE_EXCHANGE
// #define RSA_DE_EXCHANGE
// #define ECC_KEY_EXCHANGE
// #define ECC_IMPORT_ENC_KEY
// #define RSA_IMPORT_ENC_KEY
// #define KEK_SESS
// //#define MAC
// #define MAC_STANDARD_TEST
// #define HASH
// #define HASH_Z
// #define HASH_SCATTER_TEST
// #define HASH_KEY
// ///#define KEY_ACCESS_RIGHT
// #define IMPORT_KEY
// #define DEVFILE
// #define SYMM_VALIDITY_TEST
// #define ASYMM_VALIDITY_TEST
// #define HASH_VALIDITY_TEST
// #define RSA_VALIDITY_TEST
// #define SYMM
//#define MULTI_PER
//#define THREAD_ALG
//#define THREAD_SINGLE_DEV
//#define GET_VERSION

//#define LOG


#define LOG_DATA(d, l)\
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

void print_data(const char *string, unsigned char*data, int size)
{
	int i;

	printf("---------------------------------------------\n");
	printf("%s:\n", string);
	for(i=0; i<size; i++)
	{
		printf("%02x ", data[i]);
		if((i%16) == 15)
			printf("\n");
	}
	if(size%16)
		printf("\n");
	printf("---------------------------------------------\n");
}

u32 GetAccessRight(void *hSessionHandle)
{
	u32 r;
	int i;
	
	for(i=1; i<=(SDF_MAX_KEY_INDEX); i++)
	{
		r = SDF_GetPrivateKeyAccessRight(hSessionHandle, i, "11111111", 8);
		if(r) return r; 
	}	

	return 0;
}


u32 GetDeviceInfo_Test(void *hSessionHandle)
{
	u32 r;
	DEVICEINFO devinfo;

	memset(&devinfo, 0x00, sizeof(DEVICEINFO));
	
	r = SDF_GetDeviceInfo(hSessionHandle, &devinfo);
	if(r)
	{
		printf("get device info fail:%x\n", r);
		return r;
	}
	printf("issuer name:%s\n", devinfo.IssuerName);
	printf("device name:%s\n", devinfo.DeviceName);
	printf("device serial:%16.16s\n", devinfo.DeviceSerial);
	//print_data("device serial", devinfo.DeviceSerial, sizeof(devinfo.DeviceSerial));
	printf("device version:%x\n", devinfo.DeviceVersion);
	printf("standard version:%x\n", devinfo.StandardVersion);
	printf("asym algo:%x %x\n", devinfo.AsymAlgAbility[0], devinfo.AsymAlgAbility[1]);
	printf("sym algo:%x\n", devinfo.SymAlgAbility);
	printf("hash:%x\n", devinfo.HashAlgAbility);
	printf("buffer size:%x\n", devinfo.BufferSize);

	return 0;
}

u32 RSA_Test(void *hSessionHandle)
{
	u32 r;
	RSArefPublicKey rsapubkey;
	RSArefPrivateKey rsaprikey;
	int i;
	unsigned char data[256];
	unsigned char encdata[256];
	unsigned char decdata[256];
	unsigned int datalen;
	unsigned int enclen;
	unsigned int declen;

	printf("%s()-start\n", __func__);
#if 1
	for(i=1; i<3; i++)
	{
		r = SDF_ExportEncPublicKey_RSA(hSessionHandle, i, &rsapubkey);
		if(r)
		{
			printf("export rsa enc public key fail:%x\n", r);
			return r;
		}
#ifdef LOG		
		LOG_DATA(rsapubkey.m, RSAref_MAX_LEN);
		LOG_DATA(rsapubkey.e, RSAref_MAX_LEN);
#endif				
		r = SDF_ExportSignPublicKey_RSA(hSessionHandle, i, &rsapubkey);
		if(r)
		{
			printf("export rsa sign public key fail:%x\n", r);
			return r;
		}
#ifdef LOG		
		LOG_DATA(rsapubkey.m, RSAref_MAX_LEN);
		LOG_DATA(rsapubkey.e, RSAref_MAX_LEN);
#endif		
	}
#endif
	r = SDF_GenerateKeyPair_RSA(hSessionHandle, 2048, &rsapubkey, &rsaprikey);
	if(r)
	{
		printf("generate rsa  key pair fail:%x\n", r);
		return r;		
	}
#ifdef LOG	
	printf("rsa pubkey m:\n");
	LOG_DATA(rsapubkey.m, RSAref_MAX_LEN);
	printf("rsa pubkey e:\n");
	LOG_DATA(rsapubkey.e, RSAref_MAX_LEN);
	printf("rsa prikey m:\n");
	LOG_DATA(rsaprikey.m, RSAref_MAX_LEN);
	printf("rsa prikey e:\n");
	LOG_DATA(rsaprikey.e, RSAref_MAX_LEN);
	printf("rsa prikey d:\n");
	LOG_DATA(rsaprikey.d, RSAref_MAX_LEN);
	printf("rsa prikey prime0:\n");
	LOG_DATA(rsaprikey.prime[0], RSAref_MAX_PLEN);
	printf("rsa prikey prime1:\n");
	LOG_DATA(rsaprikey.prime[1], RSAref_MAX_PLEN);
	printf("rsa prikey pexp0:\n");
	LOG_DATA(rsaprikey.pexp[0], RSAref_MAX_PLEN);
	printf("rsa prikey pexp1:\n");
	LOG_DATA(rsaprikey.pexp[1], RSAref_MAX_PLEN);
	printf("rsa prikey coef:\n");
	LOG_DATA(rsaprikey.coef, RSAref_MAX_PLEN);
#endif

	datalen = 256;
	enclen = 256;
	for(i=0; i<datalen; i++)
		data[i] = (u8)(i+0x10);
	r = SDF_ExternalPublicKeyOperation_RSA(hSessionHandle, &rsapubkey, data, datalen, encdata, &enclen);
	if(r)
	{
		printf("external rsa public key operation fail:%x\n", r);
		return r;
	}
#ifdef LOG	
	printf("rsa pub calc data:\n");
	LOG_DATA(encdata, enclen);
#endif

	declen = 256;
	r = SDF_ExternalPrivateKeyOperation_RSA(hSessionHandle, &rsaprikey, encdata, enclen, decdata, &declen);
	if(r)
	{
		printf("external rsa private key operation fail:%x\n", r);
		return r;
	}
#ifdef LOG	
	printf("rsa pri calc data:\n");
	LOG_DATA(decdata, declen);
#endif

	if((declen != datalen) || memcmp(data, decdata, datalen))
	{
		printf("%s()-source data != dec data\n", __func__);
		return 1;
	}

	printf("%s() - success\n", __func__);
	return 0;
}

u32 RSA_Calc_Test(void *hSessionHandle)
{
	u32 r;
	RSArefPublicKey rsapubkey;
	RSArefPrivateKey rsaprikey;
	int i;
	unsigned char data[256];
	unsigned char encdata[256];
	unsigned char decdata[256];
	unsigned int datalen;
	unsigned int enclen;
	unsigned int declen;

	printf("%s()-start\n", __func__);
	
	/*test rsa internal key operation*/
	//printf("test internal rsa pubkey operation\n");
	datalen = 256;
	enclen = 256;
	for(i=0; i<datalen; i++)
		data[i] = (u8)(i+0x20);
	r = SDF_InternalPublicKeyOperation_RSA(hSessionHandle, 1, data, datalen, encdata, &enclen);
	if(r)
	{
		printf("internal rsa public key operation fail:%x\n", r);
		return r;
	}
#ifdef LOG	
	LOG_DATA(encdata, enclen);
#endif

	//printf("test internal rsa prikey operation\n");
	declen = 256;
	r = SDF_InternalPrivateKeyOperation_RSA(hSessionHandle, 1, encdata, enclen, decdata, &declen);
	if(r)
	{
		printf("internal rsa private key operation fail:%x\n", r);
		return r;
	}
#ifdef LOG	
	LOG_DATA(decdata, declen);
#endif
	if((declen != datalen) || memcmp(data, decdata, datalen))
	{
		printf("%s()-source data != dec data\n", __func__);
		return 1;
	}
	printf("test rsa internal key operation success\n");

	/*test rsa external key operation*/
	r = SDF_ExportSignPublicKey_RSA(hSessionHandle, 2, &rsapubkey);
	if(r)
	{
		printf("export rsa sign public key fail:%x\n", r);
		return r;
	}

	datalen = 256;
	enclen = 256;
	for(i=0; i<datalen; i++)
		data[i] = (u8)(i+0x10);
	r = SDF_ExternalPublicKeyOperation_RSA(hSessionHandle, &rsapubkey, data, datalen, encdata, &enclen);
	if(r)
	{
		printf("external rsa public key operation fail:%x\n", r);
		return r;
	}
#ifdef LOG	
	LOG_DATA(encdata, enclen);
#endif
		
	r = SDF_InternalPrivateKeyOperation_RSA(hSessionHandle, 2, encdata, enclen, decdata, &declen);
	if(r)
	{
		printf("internal rsa private key operation fail:%x\n", r);
		return r;
	}
#ifdef LOG	
	LOG_DATA(decdata, declen);
#endif
	if((declen != datalen) || memcmp(data, decdata, datalen))
	{
		printf("%s()-source data != dec data\n", __func__);
		return 1;
	}
	printf("test rsa external key operation success\n");

	printf("%s() - success\n", __func__);
	return 0;	
}

u32  RSA_SessionKey_Test1(void *hSessionHandle)
{
	u32 r;
	int i;
	unsigned char cipher_key[0x200];
	unsigned int cipher_keylen;
	RSArefPublicKey pubkey;
	void *hKey1;
	void *hKey2;
	void *hKey3;
	unsigned char data[16];
	unsigned char encdata[16];
	unsigned char decdata[16];
	unsigned int datalen;
	unsigned int enclen;
	unsigned int declen;

#if 1
	printf("%s()-start\n", __func__);

	r = SDF_GenerateKeyWithIPK_RSA(hSessionHandle, 1, 128, cipher_key, &cipher_keylen, &hKey1);
	if(r)
	{
		printf("generate session key with rsa ipk fail:%x\n", r);
		return r;
	}
#ifdef LOG	
	print_data("hkey1:", cipher_key, cipher_keylen);
#endif

	r = SDF_ImportKeyWithISK_RSA(hSessionHandle, 1, cipher_key, cipher_keylen, &hKey2);
	if(r)
	{
		printf("import session key with rsa isk fail:%x\n", r);
		return r;
	}

	for(i=0; i<16; i++)
		data[i] = (unsigned char)i;	
	datalen = 16;
	
	r = SDF_Encrypt(hSessionHandle, hKey1, SGD_SM1_ECB, NULL, data, datalen, encdata, &enclen);
	if(r)
	{
		printf("encrypt data fail:%x\n", r);
		return r;
	}
#ifdef LOG	
	print_data("encrypt data:", encdata, enclen);
#endif

	r = SDF_Decrypt(hSessionHandle, hKey2, SGD_SM1_ECB, NULL, encdata, enclen, decdata, &declen);
	if(r)
	{
		printf("decrypt data fail:%x\n", r);
		return r;		
	}
#ifdef LOG	
	print_data("decrypt data:", decdata, declen);
#endif

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
#endif

#if 0
	pubkey.bits = 2048;
	memcpy(pubkey.m, rsa_keypair_2048, RSAref_MAX_LEN);
	r = SDF_GenerateKeyWithEPK_RSA(hSessionHandle, 128, &pubkey, cipher_key, &cipher_keylen, &hKey3);
	if(r)
	{
		printf("generate session key with rsa esk fail:%x\n", r);
		return r;
	}
#ifdef LOG	
	print_data("hkey3", cipher_key, cipher_keylen);
#endif

	r = SDF_DestroyKey(hSessionHandle, hKey3);
	if(r)
	{
		printf("destroy session key2 fail:%x\n", r);
		return r;
	}
#endif
	printf("%s() - success\n", __func__);
	return 0;
}


u32  RSA_SessionKey_Test2(void *hSessionHandle)
{
	u32 r;
	int i;
	unsigned char cipher_key[0x200];
	unsigned int cipher_keylen;
	RSArefPublicKey pubkey;
	void *hKey1;
	void *hKey2;
	unsigned char data[16];
	unsigned char encdata[16];
	unsigned char decdata[16];
	unsigned int datalen;
	unsigned int enclen;
	unsigned int declen;	

	printf("%s()-start\n", __func__);

	r = SDF_ExportEncPublicKey_RSA(hSessionHandle, 2, &pubkey);
	if(r)
	{
		printf("export rsa enc public key fail:%x\n", r);
		return r;
	}	

	r = SDF_GenerateKeyWithEPK_RSA(hSessionHandle, 128, &pubkey, cipher_key, &cipher_keylen, &hKey1);
	if(r)
	{
		printf("generate session key with rsa esk fail:%x\n", r);
		return r;
	}
#ifdef LOG	
	print_data("epk rsa cipher key", cipher_key, cipher_keylen);
#endif
	r = SDF_ImportKeyWithISK_RSA(hSessionHandle, 2, cipher_key, cipher_keylen, &hKey2);
	if(r)
	{
		printf("import session key with rsa isk fail:%x\n", r);
		return r;
	}

	for(i=0; i<16; i++)
		data[i] = (unsigned char)(i+0x20);	
	datalen = 16;
	
	r = SDF_Encrypt(hSessionHandle, hKey1, SGD_SM1_ECB, NULL, data, datalen, encdata, &enclen);
	if(r)
	{
		printf("encrypt data fail:%x\n", r);
		return r;
	}
#ifdef LOG	
	print_data("encrypt data:", encdata, enclen);
#endif
	r = SDF_Decrypt(hSessionHandle, hKey2, SGD_SM1_ECB, NULL, encdata, enclen, decdata, &declen);
	if(r)
	{
		printf("decrypt data fail:%x\n", r);
		return r;		
	}
#ifdef LOG	
	print_data("decrypt data:", decdata, declen);
#endif
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

	printf("%s()-success\n", __func__);
	return 0;
}


u32 RSA_DigitEnvelope_Test(void *hSessionHandle)
{
	u32 r;
	int i;
	unsigned char cipher_key1[0x400];
	unsigned int cipher_keylen1;
	unsigned char cipher_key2[0x400];
	unsigned int cipher_keylen2;	
	RSArefPublicKey pubkey;
	void *hKey1;
	void *hKey2;
	unsigned char data[16];
	unsigned char encdata[16];
	unsigned char decdata[16];
	unsigned int datalen;
	unsigned int enclen;
	unsigned int declen;
	
	printf("%s()-start\n", __func__);
	r = SDF_GenerateKeyWithIPK_RSA(hSessionHandle, 1, 128, cipher_key1, &cipher_keylen1, &hKey1);
	if(r)
	{
		printf("generate session key with rsa ipk fail:%x\n", r);
		return r;
	}	

	r = SDF_ExportEncPublicKey_RSA(hSessionHandle, 2, &pubkey);
	if(r)
	{
		printf("export rsa enc public key fail:%x\n", r);
		return r;
	}	

	printf("%s()-cipher_keylen1:%d\n", __func__, cipher_keylen1);
	r = SDF_ExchangeDigitEnvelopeBaseOnRSA(hSessionHandle, 1, &pubkey, cipher_key1, cipher_keylen1, cipher_key2, &cipher_keylen2);
	if(r)
	{
		printf("rsa digit envelope exchange fail:%x\n", r);
		return r;	
	}

	r = SDF_ImportKeyWithISK_RSA(hSessionHandle, 2, cipher_key2, cipher_keylen2, &hKey2);
	if(r)
	{
		printf("import session key with rsa isk fail:%x\n", r);
		return r;
	}

	for(i=0; i<16; i++)
		data[i] = (unsigned char)(i+0x20);	
	datalen = 16;
	
	r = SDF_Encrypt(hSessionHandle, hKey1, SGD_SM1_ECB, NULL, data, datalen, encdata, &enclen);
	if(r)
	{
		printf("encrypt data fail:%x\n", r);
		return r;
	}
#ifdef LOG	
	print_data("encrypt data:", encdata, enclen);
#endif

	r = SDF_Decrypt(hSessionHandle, hKey2, SGD_SM1_ECB, NULL, encdata, enclen, decdata, &declen);
	if(r)
	{
		printf("decrypt data fail:%x\n", r);
		return r;		
	}
#ifdef LOG	
	print_data("decrypt data:", decdata, declen);
#endif

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


u32 RSA1024_Test1(void *hSessionHandle)
{	
	u32 r;	
	RSArefPublicKey rsapubkey;	
	RSArefPrivateKey rsaprikey;	
	int i;	
	unsigned char data[256] = {0};	
	unsigned char encdata[256];	
	unsigned char decdata[256];	
	unsigned int datalen;	
	unsigned int enclen;	
	unsigned int declen;	

	printf("%s()-start\n", __func__);

#if 0	
	for(i=1; i<3; i++)	
	{		
		r = SDF_ExportEncPublicKey_RSA(hSessionHandle, i, &rsapubkey);		
		if(r)		
		{			
			printf("export rsa enc public key fail:%x\n", r);			
			return r;		
		}
#ifdef LOG				
		LOG_DATA(rsapubkey.m, RSAref_MAX_LEN);		
		LOG_DATA(rsapubkey.e, RSAref_MAX_LEN);
#endif						

		r = SDF_ExportSignPublicKey_RSA(hSessionHandle, i, &rsapubkey);		
		if(r)		
		{			
			printf("export rsa sign public key fail:%x\n", r);			
			return r;		
		}
#ifdef LOG				
		LOG_DATA(rsapubkey.m, RSAref_MAX_LEN);		
		LOG_DATA(rsapubkey.e, RSAref_MAX_LEN);
#endif			
	}
#endif	

	r = SDF_GenerateKeyPair_RSA(hSessionHandle, 1024, &rsapubkey, &rsaprikey);	
	if(r)	
	{		
		printf("generate rsa  key pair fail:%x\n", r);		
		return r;			
	}
#ifdef LOG		
	printf("rsa pubkey m:\n");	
	LOG_DATA(rsapubkey.m, RSAref_MAX_LEN);	
	printf("rsa pubkey e:\n");	
	LOG_DATA(rsapubkey.e, RSAref_MAX_LEN);	
	printf("rsa prikey m:\n");	
	LOG_DATA(rsaprikey.m, RSAref_MAX_LEN);	
	printf("rsa prikey e:\n");	
	LOG_DATA(rsaprikey.e, RSAref_MAX_LEN);	
	printf("rsa prikey d:\n");	
	LOG_DATA(rsaprikey.d, RSAref_MAX_LEN);	
	printf("rsa prikey prime0:\n");	
	LOG_DATA(rsaprikey.prime[0], RSAref_MAX_PLEN);	
	printf("rsa prikey prime1:\n");	
	LOG_DATA(rsaprikey.prime[1], RSAref_MAX_PLEN);	
	printf("rsa prikey pexp0:\n");	
	LOG_DATA(rsaprikey.pexp[0], RSAref_MAX_PLEN);	
	printf("rsa prikey pexp1:\n");	
	LOG_DATA(rsaprikey.pexp[1], RSAref_MAX_PLEN);	
	printf("rsa prikey coef:\n");	
	LOG_DATA(rsaprikey.coef, RSAref_MAX_PLEN);
#endif	
	datalen = 128;	
	enclen = 128;	
	for(i=1; i<(datalen-1); i++)		
		data[i] = (u8)(i+0x10);	

	r = SDF_ExternalPublicKeyOperation_RSA(hSessionHandle, &rsapubkey, data, datalen, encdata, &enclen);	
	if(r)	
	{		
		printf("external rsa public key operation fail:%x\n", r);		
		return r;	
	}
#ifdef LOG		
	printf("rsa pub calc data:\n");	
	LOG_DATA(encdata, enclen);
#endif		
	declen = 256;	
	r = SDF_ExternalPrivateKeyOperation_RSA(hSessionHandle, &rsaprikey, encdata, enclen, decdata, &declen);	
	if(r)	
	{		
		printf("external rsa private key operation fail:%x\n", r);		
		return r;	
	}
#ifdef LOG		
	printf("rsa pri calc data:\n");	
	LOG_DATA(decdata, declen);
#endif		
	if((declen != datalen) || memcmp(data, decdata, datalen))	
	{		
		printf("%s()-source data != dec data\n", __func__);		
		return 1;	
	}	

	printf("%s() - success\n", __func__);	
	return 0;
}

u32 RSA1024_Test2(void *hSessionHandle)
{
	u32 r;
	RSArefPublicKey rsapubkey;
	RSArefPrivateKey rsaprikey;
	int i;
	unsigned char data[256];
	unsigned char encdata[256];
	unsigned char decdata[256];
	unsigned int datalen;
	unsigned int enclen;
	unsigned int declen;
	
	printf("%s()-start\n", __func__);
	
	for(i=(SDF_MAX_KEY_INDEX-2); i<=(SDF_MAX_KEY_INDEX-1); i++)
	{
		r = SDF_ExportEncPublicKey_RSA(hSessionHandle, i, &rsapubkey);
		if(r)
		{
			printf("export rsa enc public key fail:%x\n", r);
			return r;
		}
#ifdef LOG		
		LOG_DATA(rsapubkey.m, RSAref_MAX_LEN);
		LOG_DATA(rsapubkey.e, RSAref_MAX_LEN);
#endif				
		r = SDF_ExportSignPublicKey_RSA(hSessionHandle, i, &rsapubkey);
		if(r)
		{
			printf("export rsa sign public key fail:%x\n", r);
			return r;
		}
#ifdef LOG		
		LOG_DATA(rsapubkey.m, RSAref_MAX_LEN);
		LOG_DATA(rsapubkey.e, RSAref_MAX_LEN);
#endif		
	}

	printf("%s() - success\n", __func__);
	return 0;
}

u32 RSA1024_ExternalKey_Test(void *hSessionHandle)
{
	u32 r;
	RSArefPublicKey rsapubkey;
	RSArefPrivateKey rsaprikey;
	int i;
//	unsigned char data[128];
	unsigned char encdata[128];
	unsigned char decdata[128];
	unsigned int datalen;
	unsigned int enclen;
	unsigned int declen;
	unsigned int offset;

	printf("%s()-start\n", __func__);
	
	u8 key[] = {
		/* m */
		0xe3,0xa9,0xa2,0x45,0x95,0x78,0x40,0x60,0xb7,0x01,0x70,0xbe,0x26,0x86,0x9b,0x28,
		0xf8,0x55,0x8d,0xd1,0x63,0xb6,0x26,0x3d,0xba,0x5b,0x3d,0x27,0xf2,0x5c,0x3f,0x4f,
		0x00,0x5c,0x18,0x4b,0x35,0x70,0x18,0xf6,0xe3,0xbe,0x50,0x51,0x29,0x2b,0x79,0xf3,
		0x6c,0x2a,0xe5,0x9a,0x8e,0x56,0x4e,0x59,0x93,0x7e,0xfd,0x27,0x6d,0x6d,0xb8,0xc9,
		0x16,0xa2,0x7b,0x5c,0x21,0x63,0x9d,0xf3,0x13,0x33,0x86,0x5d,0x0c,0x4c,0x4d,0x54,
		0x59,0x24,0xb3,0x96,0xeb,0xb4,0xa8,0x4d,0x0d,0x44,0x40,0xb1,0xc0,0xdf,0x98,0x4c,
		0x70,0xa3,0xd4,0xef,0x5e,0x02,0x66,0x8c,0xa9,0xcc,0x31,0xc7,0x52,0x8c,0xca,0x7e,
		0x06,0xf3,0x94,0x75,0x47,0x98,0x4b,0x54,0x7a,0x68,0x95,0x94,0xc2,0x33,0x99,0xb7,
		/* e */
		//0x01,0x00,0x01
		/* p */
		0xbf,0xcb,0xf1,0xf1,0xea,0x02,0x01,0xed,0x56,0x81,0xb0,0x17,0x6c,0x10,0x9d,0x20,
		0x65,0xe7,0xad,0x49,0x8d,0x3e,0xcd,0x72,0xb2,0x09,0xff,0x93,0xa1,0x29,0x80,0x17,
		0x67,0x0e,0x27,0x10,0x66,0x83,0x4b,0xfa,0x63,0x25,0x93,0x90,0x49,0x58,0x3f,0x69,
		0x5b,0xec,0xb3,0x63,0x02,0x5e,0x1a,0x86,0x6a,0x4a,0x51,0x6d,0xdf,0x5e,0x71,0xdc,
		/* q */
		0xdd,0xba,0x63,0xd1,0xe0,0x3f,0x56,0x4d,0xad,0xda,0xf9,0x4a,0x36,0xae,0x6e,0xed,
		0xb4,0x60,0x60,0x09,0x9a,0x44,0x2c,0x63,0xbf,0xc9,0x16,0x3c,0xae,0x64,0x3c,0xfe,
		0xe1,0xcc,0x73,0x7f,0x1a,0x33,0x05,0x53,0x4d,0x95,0xd6,0x03,0x42,0x83,0x82,0x03,
		0xff,0xa7,0x17,0x90,0x22,0xc7,0xd0,0x9c,0xaa,0x79,0xd3,0xfb,0x60,0x6f,0x36,0xd5,
		/* dp */
		0x07,0x6d,0x22,0x64,0xb1,0xa4,0x37,0x51,0x12,0x3d,0x47,0xf4,0x74,0xa5,0xf8,0x56,
		0xec,0x5d,0x75,0x0e,0xb4,0x2a,0xb7,0xe5,0x24,0xe8,0x78,0x83,0x9f,0xdc,0xd0,0xfb,
		0x88,0x18,0x4d,0xbb,0x8c,0xfb,0x58,0xef,0xee,0xe1,0x62,0x3b,0x83,0x22,0x8e,0x3d,
		0xc5,0x4b,0x92,0xbb,0xee,0x45,0x3f,0xde,0x61,0x3d,0x3f,0x07,0x7e,0x4b,0x1a,0x4f,
		/* dq */
		0xcd,0x95,0xf2,0xa4,0x0a,0xd6,0x14,0x0a,0xe0,0x92,0xce,0x94,0x26,0xf4,0x8b,0xab,
		0x75,0x1f,0x22,0xa5,0x45,0x9a,0x61,0x73,0xd2,0x7d,0x25,0x8d,0xce,0xb7,0x9c,0x07,
		0xb5,0xb9,0x17,0xe7,0xd1,0xaa,0xdb,0x4a,0x8e,0x2f,0x2f,0xd2,0x47,0x6f,0x90,0x7c,
		0xf7,0x0a,0x6b,0xcd,0x55,0x4e,0x86,0x63,0x95,0x27,0xa8,0x53,0x2e,0xa5,0x86,0xa2,
		/* coef */
		0xcc,0xda,0x66,0xda,0xb6,0xbc,0x8c,0x3f,0xc9,0x2c,0xdc,0xb8,0x35,0x2d,0x0c,0x19,
		0x70,0x61,0x2c,0x62,0x32,0x1a,0x22,0x09,0x9a,0x4d,0xeb,0x04,0xf2,0x1d,0x3b,0x0f,
		0x5a,0xb6,0x61,0xcd,0xec,0x6c,0x22,0x62,0x26,0x3e,0xd7,0xc1,0x3e,0x5b,0x8c,0xcc,
		0x09,0x60,0xf9,0x57,0x04,0xae,0x37,0xa7,0x1f,0xa1,0x6b,0x34,0x44,0xc4,0xeb,0x23,
		/* d */
		0x31,0x48,0x97,0x89,0x3c,0x53,0x1a,0xfa,0x2b,0xd4,0x8d,0xc3,0x0b,0x3e,0x3e,0x65,
		0x46,0x8d,0xbe,0xb2,0x77,0x67,0x0a,0x20,0xe4,0x19,0xf1,0x54,0x34,0xf6,0xa3,0xd2,
		0xd8,0x7a,0x68,0xfe,0x29,0x92,0xde,0x00,0x3f,0x9a,0x5c,0x3c,0x29,0x1f,0xd7,0xc0,
		0x28,0x4d,0x86,0xd9,0x36,0xbb,0xbc,0x09,0xcd,0xd0,0x35,0xd0,0xe0,0x3a,0x02,0xbf,
		0x98,0x06,0x65,0x0e,0x2a,0x5b,0x6a,0xdd,0x2b,0x9e,0xe1,0x7c,0x8e,0x29,0xfe,0xce,
		0x01,0xf0,0x3d,0x93,0xe6,0x93,0x53,0xcf,0xc7,0xc4,0x66,0xa3,0x7a,0x0b,0x7f,0xdc,
		0x6b,0xe1,0x1b,0x46,0x70,0x3b,0xe2,0xc6,0xd2,0x13,0xc4,0xb8,0x11,0xa9,0x6c,0x28,
		0x57,0xfd,0xf1,0xdc,0x5b,0x1e,0x12,0xbc,0xc2,0x85,0xa4,0x4b,0x96,0xd8,0x8b,0x78};

	u8 data[] = {
		0x00,0x01,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
		0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
		0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
		0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
		0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
		0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0x00,0x30,0x21,0x30,
		0x09,0x06,0x05,0x2b,0x0e,0x03,0x02,0x1a,0x05,0x00,0x04,0x14,0x31,0xe6,0xc2,0xd2,
		0x8f,0x39,0x8a,0x77,0xe5,0x3c,0x00,0xcf,0xa1,0x4d,0xd9,0xbe,0x2c,0xce,0x61,0xcb};

	u8 stddata[] = {
		0x9b,0x4d,0xaa,0x8e,0xea,0x61,0x32,0xe2,0x89,0xb5,0xb9,0x33,0xa9,0x21,0xe7,0x75,
		0x6d,0x7d,0xd6,0x0d,0xf9,0x75,0xa5,0x5f,0x77,0xf0,0x03,0x5e,0x07,0x08,0xfa,0x32,
		0xeb,0x71,0xaf,0xf0,0x6e,0x4c,0x18,0x7a,0x60,0x70,0x98,0x5e,0x54,0x43,0xc0,0xea,
		0x39,0x43,0xfa,0x56,0xf8,0x8c,0x31,0xdb,0x56,0x74,0x28,0xf4,0x37,0x34,0x36,0x0c,
		0x6b,0xbf,0xfa,0xe5,0xaa,0xbd,0x4d,0x16,0xb4,0x1b,0xd8,0x4d,0x44,0xc7,0x6e,0xd5,
		0xf8,0x10,0x7b,0x5c,0x60,0xf5,0x7a,0x07,0x34,0xc9,0x4e,0x95,0x32,0xc7,0xe9,0x7d,
		0x2a,0x63,0xe4,0x07,0xa8,0x1b,0x90,0xa9,0x27,0xc6,0xb4,0xac,0xb4,0x0e,0x71,0x40,
		0xa3,0x5a,0xea,0x86,0xe6,0x4c,0x3b,0xd6,0x0d,0xa0,0xef,0x4e,0x1b,0x81,0x0b,0x4a};

	memset(&rsapubkey, 0x00, sizeof(RSArefPublicKey));
	memset(&rsaprikey, 0x00, sizeof(RSArefPrivateKey));

	c_reverse(stddata, 128);
	offset = 128;
	rsapubkey.bits = 1024;
	memcpy(rsapubkey.m+offset, key, rsapubkey.bits/8);
	c_reverse(rsapubkey.m+offset, rsapubkey.bits/8);

	
	rsaprikey.bits = 1024;
	memcpy(rsaprikey.m+offset, key, rsaprikey.bits/8);
	c_reverse(rsaprikey.m+offset, rsaprikey.bits/8);
	
	memcpy(rsaprikey.prime[0]+offset/2, key+(rsaprikey.bits/16)*2, rsaprikey.bits/16);
	c_reverse(rsaprikey.prime[0]+offset/2, rsaprikey.bits/16);

	memcpy(rsaprikey.prime[1]+offset/2, key+(rsaprikey.bits/16)*3, rsaprikey.bits/16);
	c_reverse(rsaprikey.prime[1]+offset/2, rsaprikey.bits/16);
	
	memcpy(rsaprikey.pexp[0]+offset/2, key+(rsaprikey.bits/16)*4, rsaprikey.bits/16);
	c_reverse(rsaprikey.pexp[0]+offset/2, rsaprikey.bits/16);

	memcpy(rsaprikey.pexp[1]+offset/2, key+(rsaprikey.bits/16)*5, rsaprikey.bits/16);
	c_reverse(rsaprikey.pexp[1]+offset/2, rsaprikey.bits/16);

	memcpy(rsaprikey.coef+offset/2, key+(rsaprikey.bits/16)*6, rsaprikey.bits/16);
	c_reverse(rsaprikey.coef+offset/2, rsaprikey.bits/16);

	memcpy(rsaprikey.d+offset, key+(rsaprikey.bits/16)*7, rsaprikey.bits/8);
	c_reverse(rsaprikey.d+offset, rsaprikey.bits/8);

	datalen = 128;
	enclen = 128;
#ifdef LOG	
	printf("std data:\n");
	LOG_DATA(stddata, 128);
#endif
	r = SDF_ExternalPublicKeyOperation_RSA(hSessionHandle, &rsapubkey, stddata, datalen, encdata, &enclen);
	if(r)
	{
		printf("external rsa public key operation fail:%x\n", r);
		return r;
	}
#ifdef LOG	
	printf("enc data:\n");
	LOG_DATA(encdata, enclen);
#endif	
	if((enclen != datalen) || memcmp(data, encdata, datalen))
	{
		printf("%s()-std data != enc data\n", __func__);
		return 1;
	}
	
	declen = 128;
	r = SDF_ExternalPrivateKeyOperation_RSA(hSessionHandle, &rsaprikey, encdata, enclen, decdata, &declen);
	if(r)
	{
		printf("external rsa private key operation fail:%x\n", r);
		return r;
	}
#ifdef LOG	
	printf("dec data:\n");
	LOG_DATA(decdata, declen);
#endif	
	if((declen != datalen) || memcmp(stddata, decdata, datalen))
	{
		printf("%s()-source data != dec data\n", __func__);
		return 1;
	}

	printf("%s() - success\n", __func__);
	return 0;	
}

u32 RSA1024_InternalKey_Test(void *hSessionHandle)
{
	u32 r;
	RSArefPublicKey rsapubkey;
	RSArefPrivateKey rsaprikey;
	int i;
//	unsigned char data[128];
	unsigned char encdata[128];
	unsigned char decdata[128];
	unsigned int datalen;
	unsigned int enclen;
	unsigned int declen;
	unsigned int offset;
	int key_index;

	u8 data[] = {
		0x00,0x01,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
		0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
		0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
		0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
		0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
		0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0x00,0x30,0x21,0x30,
		0x09,0x06,0x05,0x2b,0x0e,0x03,0x02,0x1a,0x05,0x00,0x04,0x14,0x31,0xe6,0xc2,0xd2,
		0x8f,0x39,0x8a,0x77,0xe5,0x3c,0x00,0xcf,0xa1,0x4d,0xd9,0xbe,0x2c,0xce,0x61,0xcb};

	u8 stddata[] = {
		0x9b,0x4d,0xaa,0x8e,0xea,0x61,0x32,0xe2,0x89,0xb5,0xb9,0x33,0xa9,0x21,0xe7,0x75,
		0x6d,0x7d,0xd6,0x0d,0xf9,0x75,0xa5,0x5f,0x77,0xf0,0x03,0x5e,0x07,0x08,0xfa,0x32,
		0xeb,0x71,0xaf,0xf0,0x6e,0x4c,0x18,0x7a,0x60,0x70,0x98,0x5e,0x54,0x43,0xc0,0xea,
		0x39,0x43,0xfa,0x56,0xf8,0x8c,0x31,0xdb,0x56,0x74,0x28,0xf4,0x37,0x34,0x36,0x0c,
		0x6b,0xbf,0xfa,0xe5,0xaa,0xbd,0x4d,0x16,0xb4,0x1b,0xd8,0x4d,0x44,0xc7,0x6e,0xd5,
		0xf8,0x10,0x7b,0x5c,0x60,0xf5,0x7a,0x07,0x34,0xc9,0x4e,0x95,0x32,0xc7,0xe9,0x7d,
		0x2a,0x63,0xe4,0x07,0xa8,0x1b,0x90,0xa9,0x27,0xc6,0xb4,0xac,0xb4,0x0e,0x71,0x40,
		0xa3,0x5a,0xea,0x86,0xe6,0x4c,0x3b,0xd6,0x0d,0xa0,0xef,0x4e,0x1b,0x81,0x0b,0x4a};

	printf("%s()-start\n", __func__);

	c_reverse(stddata, 128);
	key_index = (SDF_MAX_KEY_INDEX-1);
	datalen = 128;
	enclen = 256;
	r = SDF_InternalPublicKeyOperation_RSA(hSessionHandle, key_index, stddata, datalen, encdata, &enclen);
	if(r)
	{
		printf("internal rsa public key operation fail:%x\n", r);
		return r;
	}
#ifdef LOG	
	printf("%s()-internal pubkey enclen:%d\n", __func__, enclen);
	LOG_DATA(encdata, enclen);
#endif	
	if((enclen != datalen) || memcmp(data, encdata, datalen))
	{
		printf("%s()-std data != enc data\n", __func__);
		return 1;
	}

	//printf("test internal rsa prikey operation\n");
	declen = 256;
	r = SDF_InternalPrivateKeyOperation_RSA(hSessionHandle, key_index, encdata, enclen, decdata, &declen);
	if(r)
	{
		printf("internal rsa private key operation fail:%x\n", r);
		return r;
	}
#ifdef LOG	
	printf("%s()-internal prikey declen:%d\n", __func__, declen);
	LOG_DATA(decdata, declen);	
#endif	
	if((declen != datalen) || memcmp(stddata, decdata, datalen))
	{
		printf("%s()-source data != dec data\n", __func__);
		return 1;
	}
	printf("test rsa internal key operation success\n");



	/*test rsa external key operation*/
	r = SDF_ExportEncPublicKey_RSA(hSessionHandle, key_index, &rsapubkey);
	if(r)
	{
		printf("export rsa sign public key fail:%x\n", r);
		return r;
	}

	datalen = 128;
	enclen = 256;
	r = SDF_ExternalPublicKeyOperation_RSA(hSessionHandle, &rsapubkey, stddata, datalen, encdata, &enclen);
	if(r)
	{
		printf("external rsa public key operation fail:%x\n", r);
		return r;
	}
#ifdef LOG	
	printf("%s()-external pubkey declen:%d\n", __func__, declen);
	LOG_DATA(encdata, enclen);
#endif	
	if((enclen != datalen) || memcmp(data, encdata, datalen))
	{
		printf("%s()-std data != enc data\n", __func__);
		return 1;
	}
	
	declen = 256;	
	r = SDF_InternalPrivateKeyOperation_RSA(hSessionHandle, key_index, encdata, enclen, decdata, &declen);
	if(r)
	{
		printf("internal rsa private key operation fail:%x\n", r);
		return r;
	}
#ifdef LOG	
	printf("%s()-external prikey declen:%d\n", __func__, declen);
	LOG_DATA(decdata, declen);
#endif	
	if((declen != datalen) || memcmp(stddata, decdata, datalen))
	{
		printf("%s()-source data != dec data\n", __func__);
		return 1;
	}
	printf("test rsa external key operation success\n");
	
	printf("%s() - success\n", __func__);
	return 0;	
}

u32 RSA1024_SessionKey_Test1(void *hSessionHandle)
{
	u32 r;
	int i;
	unsigned char cipher_key[0x200];
	unsigned int cipher_keylen;
	RSArefPublicKey pubkey;
	void *hKey1;
	void *hKey2;
	void *hKey3;
	unsigned char data[16];
	unsigned char encdata[16];
	unsigned char decdata[16];
	unsigned int datalen;
	unsigned int enclen;
	unsigned int declen;

#if 1
	printf("%s()-start\n", __func__);

	r = SDF_GenerateKeyWithIPK_RSA(hSessionHandle, (SDF_MAX_KEY_INDEX-2), 128, cipher_key, &cipher_keylen, &hKey1);
	if(r)
	{
		printf("generate session key with rsa ipk fail:%x\n", r);
		return r;
	}
#ifdef LOG	
	print_data("hkey1:", cipher_key, cipher_keylen);
#endif
	r = SDF_ImportKeyWithISK_RSA(hSessionHandle, (SDF_MAX_KEY_INDEX-2), cipher_key, cipher_keylen, &hKey2);
	if(r)
	{
		printf("import session key with rsa isk fail:%x\n", r);
		return r;
	}

	for(i=0; i<16; i++)
		data[i] = (unsigned char)i;	
	datalen = 16;
	
	r = SDF_Encrypt(hSessionHandle, hKey1, SGD_SM1_ECB, NULL, data, datalen, encdata, &enclen);
	if(r)
	{
		printf("encrypt data fail:%x\n", r);
		return r;
	}
#ifdef LOG	
	print_data("encrypt data:", encdata, enclen);
#endif
	r = SDF_Decrypt(hSessionHandle, hKey2, SGD_SM1_ECB, NULL, encdata, enclen, decdata, &declen);
	if(r)
	{
		printf("decrypt data fail:%x\n", r);
		return r;		
	}
#ifdef LOG	
	print_data("decrypt data:", decdata, declen);
#endif
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
#endif

	printf("%s() - success\n", __func__);
	return 0;
}


u32 RSA1024_SessionKey_Test2(void *hSessionHandle)
{
	u32 r;
	int i;
	unsigned char cipher_key[0x200];
	unsigned int cipher_keylen;
	RSArefPublicKey pubkey;
	void *hKey1;
	void *hKey2;
	unsigned char data[16];
	unsigned char encdata[16];
	unsigned char decdata[16];
	unsigned int datalen;
	unsigned int enclen;
	unsigned int declen;	

	printf("%s()-start\n", __func__);

	r = SDF_ExportEncPublicKey_RSA(hSessionHandle, (SDF_MAX_KEY_INDEX-2), &pubkey);
	if(r)
	{
		printf("export rsa enc public key fail:%x\n", r);
		return r;
	}	

	r = SDF_GenerateKeyWithEPK_RSA(hSessionHandle, 128, &pubkey, cipher_key, &cipher_keylen, &hKey1);
	if(r)
	{
		printf("generate session key with rsa esk fail:%x\n", r);
		return r;
	}
#ifdef LOG	
	print_data("epk rsa cipher key", cipher_key, cipher_keylen);
#endif
	r = SDF_ImportKeyWithISK_RSA(hSessionHandle, (SDF_MAX_KEY_INDEX-2), cipher_key, cipher_keylen, &hKey2);
	if(r)
	{
		printf("import session key with rsa isk fail:%x\n", r);
		return r;
	}

	for(i=0; i<16; i++)
		data[i] = (unsigned char)(i+0x20);	
	datalen = 16;
	
	r = SDF_Encrypt(hSessionHandle, hKey1, SGD_SM1_ECB, NULL, data, datalen, encdata, &enclen);
	if(r)
	{
		printf("encrypt data fail:%x\n", r);
		return r;
	}
#ifdef LOG	
	print_data("encrypt data:", encdata, enclen);
#endif
	r = SDF_Decrypt(hSessionHandle, hKey2, SGD_SM1_ECB, NULL, encdata, enclen, decdata, &declen);
	if(r)
	{
		printf("decrypt data fail:%x\n", r);
		return r;		
	}
#ifdef LOG	
	print_data("decrypt data:", decdata, declen);
#endif
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

	printf("%s()-success\n", __func__);
	return 0;
}


u32 RSA_ImportEncKey_Test(void *hSessionHandle)
{
	u32 r,i;
	RSArefPublicKey signpubkey;
	RSArefPublicKey encrsapubkey;
	RSArefPrivateKey encrsaprikey;
	void *hKey;
	u8 symmkey[256];
	u32 symmkeylen;
	u8 srckeypair[1152];
	u8 enckeypair[1152];
	u32 keypairlen;
	u32 keyindex;
	unsigned char cipher_key[0x200];
	unsigned int cipher_keylen;
	void *hKey1;
	void *hKey2;
	unsigned char data[16];
	unsigned char encdata[16];
	unsigned char decdata[16];
	unsigned int datalen;
	unsigned int enclen;
	unsigned int declen;
	
	keyindex = SDF_MAX_KEY_INDEX;
	r = EVDF_DeleteInternalKeyPair_RSA(hSessionHandle, 0, keyindex, "11111111");
	if(r)
	{
		printf("EVDF_DeleteInternalKeyPair_RSA fail:%x\n", r);
	}


	r = SDF_ExportSignPublicKey_RSA(hSessionHandle, keyindex, &signpubkey);
	if(r)
	{
		printf("SDF_ExportSignPublicKey_RSA fail:%x\n", r);
		return r;
	}

	r = SDF_GenerateKeyPair_RSA(hSessionHandle, 2048, &encrsapubkey, &encrsaprikey);
	if(r)
	{
		printf("SDF_GenerateKeyPair_RSA fail:%x\n", r);
		return r;
	}
	memcpy(&srckeypair[0], encrsaprikey.m, 256);
	memcpy(&srckeypair[128*2], encrsaprikey.prime[0], 128);
	memcpy(&srckeypair[128*3], encrsaprikey.prime[1], 128);
	memcpy(&srckeypair[128*4], encrsaprikey.pexp[0], 128);
	memcpy(&srckeypair[128*5], encrsaprikey.pexp[1], 128);
	memcpy(&srckeypair[128*6], encrsaprikey.coef, 128);
	memcpy(&srckeypair[128*7], encrsaprikey.d, 256);
#ifdef LOG		
	printf("import keypair:\n");
	LOG_DATA(srckeypair, 1152);
#endif		

	r = SDF_GenerateKeyWithEPK_RSA(hSessionHandle, 128, &signpubkey, symmkey, &symmkeylen, &hKey);
	if(r)
	{
		printf("SDF_GenerateKeyWithEPK_RSA fail:%x\n", r);
		return r;
	}
#ifdef LOG		
	printf("encrypt symm key:\n");
	LOG_DATA(symmkey, symmkeylen);
#endif	

	//calc keypair
	r = SDF_Encrypt(hSessionHandle, hKey, SGD_SMS4_ECB, NULL, &srckeypair[0], 1152, &enckeypair[0], &keypairlen);
	if(r)
	{
		printf("encrypt data fail:%x\n", r);
		return r;
	}

	r = EVDF_ImportEncKeyPair_RSA(hSessionHandle, keyindex, SGD_SMS4_ECB, symmkey, symmkeylen, enckeypair, keypairlen);
	if(r)
	{
		printf("encrypt data fail:%x\n", r);
		return r;
	}	

	r = SDF_DestroyKey(hSessionHandle, hKey);
	if(r)
	{
		printf("SDF_DestroyKey fail:%x\n", r);
		return r;
	}
	
	//check
#if 0	

#else
	r = SDF_GenerateKeyWithEPK_RSA(hSessionHandle, 128, &encrsapubkey, cipher_key, &cipher_keylen, &hKey1);
	if(r)
	{
		printf("generate session key with rsa esk fail:%x\n", r);
		return r;
	}
#ifdef LOG	
	print_data("epk rsa cipher key", cipher_key, cipher_keylen);
#endif
	r = SDF_ImportKeyWithISK_RSA(hSessionHandle, keyindex, cipher_key, cipher_keylen, &hKey2);
	if(r)
	{
		printf("import session key with rsa isk fail:%x\n", r);
		return r;
	}

	for(i=0; i<16; i++)
		data[i] = (unsigned char)(i+0x20);	
	datalen = 16;
	
	r = SDF_Encrypt(hSessionHandle, hKey1, SGD_SM1_ECB, NULL, data, datalen, encdata, &enclen);
	if(r)
	{
		printf("encrypt data fail:%x\n", r);
		return r;
	}
#ifdef LOG	
	print_data("encrypt data:", encdata, enclen);
#endif
	r = SDF_Decrypt(hSessionHandle, hKey2, SGD_SM1_ECB, NULL, encdata, enclen, decdata, &declen);
	if(r)
	{
		printf("decrypt data fail:%x\n", r);
		return r;		
	}
#ifdef LOG	
	print_data("decrypt data:", decdata, declen);
#endif
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
#endif

	printf("%s()-success\n", __func__);
	return 0;	
	
}

u32 RSA1024_DigitEnvelope_Test(void *hSessionHandle)
{
	u32 r;
	int i;
	unsigned char cipher_key1[0x400];
	unsigned int cipher_keylen1;
	unsigned char cipher_key2[0x400];
	unsigned int cipher_keylen2;	
	RSArefPublicKey pubkey;
	void *hKey1;
	void *hKey2;
	unsigned char data[16];
	unsigned char encdata[16];
	unsigned char decdata[16];
	unsigned int datalen;
	unsigned int enclen;
	unsigned int declen;
	
	printf("%s()-start\n", __func__);
	r = SDF_GenerateKeyWithIPK_RSA(hSessionHandle, (SDF_MAX_KEY_INDEX-2), 128, cipher_key1, &cipher_keylen1, &hKey1);
	if(r)
	{
		printf("generate session key with rsa ipk fail:%x\n", r);
		return r;
	}	

	r = SDF_ExportEncPublicKey_RSA(hSessionHandle, (SDF_MAX_KEY_INDEX-1), &pubkey);
	if(r)
	{
		printf("export rsa enc public key fail:%x\n", r);
		return r;
	}	
	printf("pubkey bitlen:%d\n", pubkey.bits);

	r = SDF_ExchangeDigitEnvelopeBaseOnRSA(hSessionHandle, (SDF_MAX_KEY_INDEX-2), &pubkey, cipher_key1, cipher_keylen1, cipher_key2, &cipher_keylen2);
	if(r)
	{
		printf("rsa digit envelope exchange fail:%x\n", r);
		return r;	
	}

	r = SDF_ImportKeyWithISK_RSA(hSessionHandle, (SDF_MAX_KEY_INDEX-1), cipher_key2, cipher_keylen2, &hKey2);
	if(r)
	{
		printf("import session key with rsa isk fail:%x\n", r);
		return r;
	}

	for(i=0; i<16; i++)
		data[i] = (unsigned char)(i+0x20);	
	datalen = 16;
	
	r = SDF_Encrypt(hSessionHandle, hKey1, SGD_SM1_ECB, NULL, data, datalen, encdata, &enclen);
	if(r)
	{
		printf("encrypt data fail:%x\n", r);
		return r;
	}
#ifdef LOG	
	print_data("encrypt data:", encdata, enclen);
#endif
	r = SDF_Decrypt(hSessionHandle, hKey2, SGD_SM1_ECB, NULL, encdata, enclen, decdata, &declen);
	if(r)
	{
		printf("decrypt data fail:%x\n", r);
		return r;		
	}
#ifdef LOG	
	print_data("decrypt data:", decdata, declen);
#endif
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

u32 ECC_Test(void *hSessionHandle)
{
	u32 r;
	ECCrefPublicKey eccpubkey;
	ECCrefPrivateKey eccprikey;
	ECCSignature sig;
	int i;
	unsigned char data[32];
	unsigned char encdata[256];
	unsigned char decdata[256];
	int declen;
	ECCCipher *pecccipher = (ECCCipher *)encdata;

	printf("%s()-start\n", __func__);
#if 1
	for(i=1; i<3; i++)
	{
		printf("%s()-test ExportSignPublicKey\n", __func__);
		r = SDF_ExportSignPublicKey_ECC(hSessionHandle, i, &eccpubkey);
		if(r)
		{
			printf("export ecc enc public key fail:%x\n", r);
			return r;
		}
#ifdef LOG		
		LOG_DATA(eccpubkey.x, ECCref_MAX_LEN);
		LOG_DATA(eccpubkey.y, ECCref_MAX_LEN);
#endif		
		printf("%s()-test ExportEncPublicKey\n", __func__);
		r = SDF_ExportEncPublicKey_ECC(hSessionHandle, i, &eccpubkey);
		if(r)
		{
			printf("export ecc sign public key fail:%x\n", r);
			return r;
		}
#ifdef LOG		
		LOG_DATA(eccpubkey.x, ECCref_MAX_LEN);
		LOG_DATA(eccpubkey.y, ECCref_MAX_LEN);		
#endif		
	}
#endif
	r = SDF_GenerateKeyPair_ECC(hSessionHandle, SGD_SM2_1, 256, &eccpubkey, &eccprikey);
	if(r)
	{
		printf("generate ecc key pair fail:%x\n", r);
		return r;
	}
#ifdef LOG	
	LOG_DATA(eccpubkey.x, ECCref_MAX_LEN);
	LOG_DATA(eccpubkey.y, ECCref_MAX_LEN);
	LOG_DATA(eccprikey.K, ECCref_MAX_LEN);
#endif

	for(i=0; i<32; i++)
		data[i] = (u8)(i+0x80);	
	r = SDF_ExternalSign_ECC(hSessionHandle, SGD_SM2_1, &eccprikey, data, 32, &sig);
	if(r)
	{
		printf("external ecc sign fail:%x\n", r);
		return r;
	}

	r = SDF_ExternalVerify_ECC(hSessionHandle, SGD_SM2_1, &eccpubkey, data, 32, &sig);
	if(r)
	{
		printf("external ecc verify fail:%x\n", r);
		return r;
	}
	
	printf("%s() - success\n", __func__);
	return 0;
}


u32 ECC_Calc_Test(void *hSessionHandle)
{
	u32 r;
	ECCrefPublicKey eccpubkey;
	ECCrefPrivateKey eccprikey;
	ECCSignature sig;
	int i;
	unsigned char data[32];
	unsigned char encdata[256];
	unsigned char decdata[256];
	int declen;
	ECCCipher *pecccipher = (ECCCipher *)encdata;	

	u8 keypair[] = {
		//x
		0x19, 0x79, 0x5d, 0xf7, 0x01, 0xf3, 0x9d, 0x1f, 0xb2, 0x20, 0xc4, 0x5f, 0xa7, 0xfa, 0x4e, 0xbf, 
		0xad, 0xd1, 0x70, 0x25, 0x37, 0xb9, 0x46, 0xcd, 0x3d, 0x48, 0x04, 0xb3, 0x7f, 0xbc, 0x3e, 0xa5,
		//y
		0x2b, 0x2c, 0xee, 0xd6, 0xcc, 0x04, 0x2b, 0x5b, 0xbb, 0x56, 0x8d, 0xed, 0x3b, 0x36, 0x73, 0xf2, 
		0x88, 0xe1, 0x9c, 0xc4, 0x9a, 0xe3, 0xc3, 0x50, 0xd2, 0xb8, 0x09, 0x03, 0xd8, 0x6d, 0x91, 0x2c,
		//d
		0x3f, 0x91, 0x68, 0xe8, 0x6d, 0x2a, 0xac, 0xaa, 0x2c, 0x81, 0xd8, 0xba, 0x24, 0x9b, 0xc9, 0x5a, 
		0x60, 0xe0, 0x47, 0x50, 0xa2, 0xee, 0xaa, 0x63, 0x26, 0x2b, 0x54, 0xc4, 0x75, 0x51, 0xb8, 0xdc
	};	

	printf("%s()-start\n", __func__);

	printf("%s()-test InternalSign\n", __func__);
	memset(data, 1, 32);
	r = SDF_InternalSign_ECC(hSessionHandle, 1, data, 32, &sig);
	if(r)
	{
		printf("internal ecc sign data fail:%x\n", r);
		return r;
	}
#ifdef LOG	
	LOG_DATA(sig.r, ECCref_MAX_LEN);
	LOG_DATA(sig.s, ECCref_MAX_LEN);	
#endif

	printf("%s()-test InternalVerify\n", __func__);
	r = SDF_InternalVerify_ECC(hSessionHandle, 1, data, 32, &sig);
	if(r)
	{
		printf("internal ecc verify fail:%x\n", r);
		return r;
	}
	printf("internal ecc verify success\n");

	printf("%s()-test ExternalVerify\n", __func__);
	r = SDF_ExportSignPublicKey_ECC(hSessionHandle, 1, &eccpubkey);
	if(r)
	{
		printf("export ecc enc public key fail:%x\n", r);
		return r;
	}
	r = SDF_ExternalVerify_ECC(hSessionHandle, SGD_SM2_1, &eccpubkey, data, 32, &sig);
	if(r)
	{
		printf("external ecc verify fail:%x\n", r);
		return r;
	}
	printf("external ecc verify success\n");

	printf("%s() - success\n", __func__);
	return 0;
}



u32  ECC_SessionKey_Test1(void *hSessionHandle)
{
	u32 r;
	void *hKey1;
	void *hKey2;
	void *hKey3;
	unsigned char cipherdata[256];
	ECCCipher *pecccipher = (ECCCipher *)cipherdata; 
	ECCrefPublicKey eccpubkey;
	u8 keypair[] = {
		//x
		0x19, 0x79, 0x5d, 0xf7, 0x01, 0xf3, 0x9d, 0x1f, 0xb2, 0x20, 0xc4, 0x5f, 0xa7, 0xfa, 0x4e, 0xbf, 
		0xad, 0xd1, 0x70, 0x25, 0x37, 0xb9, 0x46, 0xcd, 0x3d, 0x48, 0x04, 0xb3, 0x7f, 0xbc, 0x3e, 0xa5,
		//y
		0x2b, 0x2c, 0xee, 0xd6, 0xcc, 0x04, 0x2b, 0x5b, 0xbb, 0x56, 0x8d, 0xed, 0x3b, 0x36, 0x73, 0xf2, 
		0x88, 0xe1, 0x9c, 0xc4, 0x9a, 0xe3, 0xc3, 0x50, 0xd2, 0xb8, 0x09, 0x03, 0xd8, 0x6d, 0x91, 0x2c,
		//d
		0x3f, 0x91, 0x68, 0xe8, 0x6d, 0x2a, 0xac, 0xaa, 0x2c, 0x81, 0xd8, 0xba, 0x24, 0x9b, 0xc9, 0x5a, 
		0x60, 0xe0, 0x47, 0x50, 0xa2, 0xee, 0xaa, 0x63, 0x26, 0x2b, 0x54, 0xc4, 0x75, 0x51, 0xb8, 0xdc
	};
	unsigned char data[16];
	unsigned char encdata[16];
	unsigned char decdata[16];
	unsigned int datalen;
	unsigned int enclen;
	unsigned int declen;	
	int i;

	printf("%s()-start\n", __func__);

	memset(&eccpubkey, 0, sizeof(ECCrefPublicKey));
	memcpy(eccpubkey.x+32, keypair, 32);
	memcpy(eccpubkey.y+32, keypair+32, 32);
	eccpubkey.bits = 256;

	r = SDF_GenerateKeyWithEPK_ECC(hSessionHandle, 128, SGD_SM2_3, &eccpubkey, pecccipher, &hKey3);
	if(r)
	{
		printf("generate session key with ecc epk fail:%x\n", r);
		return r;
	}
#ifdef LOG	
	LOG_DATA(pecccipher->x, ECCref_MAX_LEN);
	LOG_DATA(pecccipher->y, ECCref_MAX_LEN);
	LOG_DATA(pecccipher->M, 32);
	LOG_DATA(pecccipher->C, pecccipher->L);
#endif

	r = SDF_DestroyKey(hSessionHandle, hKey3);
	if(r)
	{
		printf("destroy session key3 fail:%x\n", r);
		return r;
	}
	
	r = SDF_GenerateKeyWithIPK_ECC(hSessionHandle, 1, 128, pecccipher, &hKey1);
	if(r)
	{
		printf("generate session key with ecc ipk fail:%x\n", r);
		return r;
	}
#ifdef LOG	
	LOG_DATA(pecccipher->x, ECCref_MAX_LEN);
	LOG_DATA(pecccipher->y, ECCref_MAX_LEN);
	LOG_DATA(pecccipher->M, 32);
	LOG_DATA(pecccipher->C, pecccipher->L);
#endif

	r = SDF_ImportKeyWithISK_ECC(hSessionHandle, 1, pecccipher, &hKey2);
	if(r)
	{
		printf("import session key with ecc isk fail:%x\n", r);
		return r;
	}

	for(i=0; i<16; i++)
		data[i] = (unsigned char)(i);	
	datalen = 16;
	
	r = SDF_Encrypt(hSessionHandle, hKey1, SGD_SM1_ECB, NULL, data, datalen, encdata, &enclen);
	if(r)
	{
		printf("encrypt data fail:%x\n", r);
		return r;
	}
#ifdef LOG	
	print_data("encrypt data:", encdata, enclen);
#endif

	r = SDF_Decrypt(hSessionHandle, hKey2, SGD_SM1_ECB, NULL, encdata, enclen, decdata, &declen);
	if(r)
	{
		printf("decrypt data fail:%x\n", r);
		return r;		
	}
#ifdef LOG	
	print_data("decrypt data:", decdata, declen);
#endif

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


u32  ECC_SessionKey_Test2(void *hSessionHandle)
{
	u32 r;
	void *hKey1;
	void *hKey2;	
	ECCrefPublicKey eccpubkey;
	unsigned char cipherdata[256];
	ECCCipher *pecccipher = (ECCCipher *)cipherdata; 
	unsigned char data[16];
	unsigned char encdata[16];
	unsigned char decdata[16];
	unsigned int datalen;
	unsigned int enclen;
	unsigned int declen;	
	int i;

	printf("%s()-start\n", __func__);
	
	r = SDF_ExportEncPublicKey_ECC(hSessionHandle, 2, &eccpubkey);
	if(r)
	{
		printf("export ecc sign public key fail:%x\n", r);
		return r;
	}
#ifdef LOG	
	print_data("pubkey x", eccpubkey.x, ECCref_MAX_LEN);
	print_data("pubkey y", eccpubkey.y, ECCref_MAX_LEN);
#endif

	r = SDF_GenerateKeyWithEPK_ECC(hSessionHandle, 128, SGD_SM2_3, &eccpubkey, pecccipher, &hKey1);
	if(r)
	{
		printf("generate session key with ecc epk fail:%x\n", r);
		return r;
	}
#ifdef LOG	
	print_data("cipher data x", pecccipher->x, ECCref_MAX_LEN);
	print_data("cipher data y", pecccipher->y, ECCref_MAX_LEN);
#endif

	r = SDF_ImportKeyWithISK_ECC(hSessionHandle, 2, pecccipher, &hKey2);
	if(r)
	{
		printf("import session key with ecc isk fail:%x\n", r);
		return r;
	}

	for(i=0; i<16; i++)
		data[i] = (unsigned char)(i+0x10);	
	datalen = 16;
	
	r = SDF_Encrypt(hSessionHandle, hKey1, SGD_SM1_ECB, NULL, data, datalen, encdata, &enclen);
	if(r)
	{
		printf("encrypt data fail:%x\n", r);
		return r;
	}
#ifdef LOG	
	print_data("encrypt data:", encdata, enclen);
#endif

	r = SDF_Decrypt(hSessionHandle, hKey2, SGD_SM1_ECB, NULL, encdata, enclen, decdata, &declen);
	if(r)
	{
		printf("decrypt data fail:%x\n", r);
		return r;		
	}
#ifdef LOG	
	print_data("decrypt data:", decdata, declen);
#endif

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

u32  ECC_SessionKey_Test3(void *hSessionHandle)
{
	u32 r;
	void *hKey1;
	void *hKey2;
	ECCrefPublicKey eccpubkey;
	unsigned char cipherdata[256];
	ECCCipher *pecccipher = (ECCCipher *)cipherdata; 
	unsigned char data[16];
	unsigned char encdata[16];
	unsigned char decdata[16];
	unsigned int datalen;
	unsigned int enclen;
	unsigned int declen;	
	int i;	
	u8  key[32] = {0};	

	printf("%s()-start\n", __func__);

	srand((unsigned int)time(NULL));
	for(i=0;i<16;i++)
	{
		key[i] = (u8)rand();
	}

	r = SDF_ImportKey(hSessionHandle, key, 16, &hKey1);
	if(r)
	{
		printf("import session key fail:%x\n", r);
		return r;	
	}
	
	r = SDF_ExportEncPublicKey_ECC(hSessionHandle, 1, &eccpubkey);
	if(r)
	{
		printf("export ecc enc public key fail:%x\n", r);
		return r;
	}
#ifdef LOG	
	print_data("pubkey x", eccpubkey.x, ECCref_MAX_LEN);
	print_data("pubkey y", eccpubkey.y, ECCref_MAX_LEN);
#endif	

	r = EVDF_ExportKeyWithEPK_ECC(hSessionHandle, hKey1, &eccpubkey, pecccipher);
	if(r)
	{
		printf("export sesskey with ecc external public key fail:%x\n", r);
		return r;
	}
#ifdef LOG	
	print_data("cipher data x", pecccipher->x, ECCref_MAX_LEN);
	print_data("cipher data y", pecccipher->y, ECCref_MAX_LEN);
#endif

	r = SDF_ImportKeyWithISK_ECC(hSessionHandle, 1, pecccipher, &hKey2);
	if(r)
	{
		printf("import session key with ecc isk fail:%x\n", r);
		return r;
	}

	for(i=0; i<16; i++)
		data[i] = (unsigned char)(i+0x10);	
	datalen = 16;
	
	r = SDF_Encrypt(hSessionHandle, hKey1, SGD_SM1_ECB, NULL, data, datalen, encdata, &enclen);
	if(r)
	{
		printf("encrypt data fail:%x\n", r);
		return r;
	}
#ifdef LOG	
	print_data("encrypt data:", encdata, enclen);
#endif

	r = SDF_Decrypt(hSessionHandle, hKey2, SGD_SM1_ECB, NULL, encdata, enclen, decdata, &declen);
	if(r)
	{
		printf("decrypt data fail:%x\n", r);
		return r;		
	}
#ifdef LOG	
	print_data("decrypt data:", decdata, declen);
#endif

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



u32 ECC_ImportEncKey_Test(void *hSessionHandle)
{
	u32 r,i;
	ECCrefPublicKey eccencpubkey;
	ECCrefPrivateKey eccencprikey;
	ECCrefPublicKey eccsignpubkey;
	ENVELOPEDKEYBLOB eccblob;
	unsigned char data[32];
	unsigned char encdata[256];
	unsigned char decdata[256];
	unsigned int declen;
	ECCCipher *pecccipher = (ECCCipher *)encdata;		
	void *hKey;
	unsigned int enclen = 0;
	u8 symmkey[16] = {0};

	srand((unsigned int)time(NULL));
	for(i=0;i<16;i++)
	{
		symmkey[i] = (u8)rand();
	}

	r = EVDF_DeleteInternalKeyPair_ECC(hSessionHandle, 0, SDF_MAX_KEY_INDEX, "11111111");
	if(r)
	{
		printf("delete internal ecc enc key fail:%x\n", r);
	}

	r = SDF_ExportSignPublicKey_ECC(hSessionHandle, SDF_MAX_KEY_INDEX, &eccsignpubkey);
	if(r)
	{
		printf("export ecc sign public key fail:%x\n", r);
		return r;
	}
#ifdef LOG		
	LOG_DATA(eccsignpubkey.x, ECCref_MAX_LEN);
	LOG_DATA(eccsignpubkey.y, ECCref_MAX_LEN);
#endif

	r = SDF_GenerateKeyPair_ECC(hSessionHandle, SGD_SM2_1, 256, &eccencpubkey, &eccencprikey);
	if(r)
	{
		printf("generate ecc key pair fail:%x\n", r);
		return r;
	}
#ifdef LOG	
	LOG_DATA(eccencpubkey.x, ECCref_MAX_LEN);
	LOG_DATA(eccencpubkey.y, ECCref_MAX_LEN);
	LOG_DATA(eccencprikey.K, ECCref_MAX_LEN);
#endif


	eccblob.ulAsymmAlgID = SGD_SM2_1;
	eccblob.ulSymmAlgID = SGD_SMS4_ECB;
	memcpy(&eccblob.PubKey, &eccencpubkey, sizeof(ECCPUBLICKEYBLOB));

	//encrypt privkey
#if 0	

#else

	r = SDF_GenerateKeyWithEPK_ECC(hSessionHandle, 128, SGD_SM2_3, &eccsignpubkey, pecccipher, &hKey);
	if(r)
	{
		printf("SDF_GenerateKeyWithEPK_RSA fail:%x\n", r);
		return r;
	}
	
	//calc keypair
	r = SDF_Encrypt(hSessionHandle, hKey, SGD_SMS4_ECB, NULL, &eccencprikey.K[0], ECCref_MAX_LEN, &eccblob.cbEncryptedPrikey[0], &enclen);
	if(r)
	{
		printf("encrypt data fail:%x\n", r);
		return r;
	}

#endif

	r = SDF_DestroyKey(hSessionHandle, hKey);
	if(r)
	{
		printf("SDF_DestroyKey fail:%x\n", r);
		return r;
	}

	//import key
	memcpy(&eccblob.ECCCipherBlob.XCoordinate, &pecccipher->x, ECCref_MAX_LEN);
	memcpy(&eccblob.ECCCipherBlob.YCoordinate, &pecccipher->y, ECCref_MAX_LEN);
	memcpy(&eccblob.ECCCipherBlob.Hash, &pecccipher->M, 32);
	memcpy(&eccblob.ECCCipherBlob.Cipher, &pecccipher->C, pecccipher->L);
	eccblob.ECCCipherBlob.CipherLen = pecccipher->L;
	
	r = EVDF_ImportEncKeyPair_ECC(hSessionHandle, SDF_MAX_KEY_INDEX, &eccblob);
	if(r)
	{
		printf("import ecc enc key pair fail:%x\n", r);
		return r;
	}


	r = SDF_ExportEncPublicKey_ECC(hSessionHandle, SDF_MAX_KEY_INDEX, &eccencpubkey);
	if(r)
	{
		printf("export ecc sign public key fail:%x\n", r);
		return r;
	}
#ifdef LOG		
	LOG_DATA(eccencpubkey.x, ECCref_MAX_LEN);
	LOG_DATA(eccencpubkey.y, ECCref_MAX_LEN);
#endif

	memset(data, 2, 32);
	r = SDF_ExternalEncrypt_ECC(hSessionHandle, SGD_SM2_3, &eccencpubkey, data, 32, pecccipher);
	if(r)
	{
		printf("external ecc encrypt fail:%x\n", r);
		return r;
	}
#ifdef LOG	
	LOG_DATA(pecccipher->C, pecccipher->L);
#endif	

	declen = 100;
	r = SDF_InternalDecrypt_ECC(hSessionHandle, SDF_MAX_KEY_INDEX, pecccipher, decdata, &declen);
	if(r)
	{
		printf("internal ecc decrypt fail:%x\n", r);
		return r;
	}
#ifdef LOG	
	LOG_DATA(decdata, declen);
#endif	
	if((declen != 32) || memcmp(data, decdata, 32))
	{
		printf("%s()-source data != dec data\n", __func__);
		return 1;
	}

	printf("%s()-success\n", __func__);

	return 0;	
}

u32 ECC_DigitEnvelope_Test(void *hSessionHandle)
{
	u32 r;
	void *hKey1;
	void *hKey2;
	unsigned char cipherdata1[256];
	unsigned char cipherdata2[256];
	ECCCipher *pecccipher1 = (ECCCipher *)cipherdata1; 
	ECCCipher *pecccipher2 = (ECCCipher *)cipherdata2; 
	ECCrefPublicKey eccpubkey;
	unsigned char data[16];
	unsigned char encdata[16];
	unsigned char decdata[16];
	unsigned int datalen;
	unsigned int enclen;
	unsigned int declen;	
	int i;
		
	printf("%s()-start\n", __func__);

	r = SDF_GenerateKeyWithIPK_ECC(hSessionHandle, 1, 128, pecccipher1, &hKey1);
	if(r)
	{
		printf("generate session key with ecc ipk fail:%x\n", r);
		return r;
	}
	
	r = SDF_ExportEncPublicKey_ECC(hSessionHandle, 2, &eccpubkey);
	if(r)
	{
		printf("export ecc sign public key fail:%x\n", r);
		return r;
	}

	r = SDF_ExchangeDigitEnvelopeBaseOnECC(hSessionHandle, 1, SGD_SM2_3, &eccpubkey, pecccipher1, pecccipher2);
	if(r)
	{
		printf("ecc digit envelope exchange fail:%x\n", r);
		return r;
	}

	r = SDF_ImportKeyWithISK_ECC(hSessionHandle, 2, pecccipher2, &hKey2);
	if(r)
	{
		printf("import session key with ecc isk fail:%x\n", r);
		return r;
	}

	for(i=0; i<16; i++)
		data[i] = (unsigned char)(i+0x10);	
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


u32 ECC_ExchangeKey_Test(void *hSessionHandle)
{
	u32 r;
	int i;
	unsigned char data[16];
	unsigned char encdata[16];
	unsigned char decdata[16];
	unsigned int datalen;
	unsigned int enclen;
	unsigned int declen;
	ECCrefPublicKey PubA, PubB;
	ECCrefPublicKey PubTempA, PubTempB;
	void *hExchA = NULL;
	void *hKeyA = NULL;
	void *hKeyB = NULL;
	
	
	printf("%s()-start\n", __func__);
#if 0
	r = SDF_GetPrivateKeyAccessRight(hSessionHandle, 1, "hss.locate(gusu)", 16);
	if(r)
	{
		printf("SDF_GetPrivateKeyAccessRight1 fail:%x\n", r);
		return r;
	}

	r = SDF_GetPrivateKeyAccessRight(hSessionHandle, 2, "hss.locate(gusu)", 16);
	if(r)
	{
		printf("SDF_GetPrivateKeyAccessRight2 fail:%x\n", r);
		return r;
	}
#endif
	//A 
	memset(&PubA, 0, sizeof(ECCrefPublicKey));
	r = SDF_GenerateAgreementDataWithECC(hSessionHandle, 1, 128, (u8*)"1234567812345678", 16, &PubA, &PubTempA, &hExchA);
	if(r)
	{
		printf("SDF_GenerateAgreementDataWithECC fail:%x\n", r);
		goto err;	
	}

	//B
	r = SDF_GenerateAgreementDataAndKeyWithECC(hSessionHandle, 2, 128, (u8*)"1234567812345678", 16, (u8*)"1234567812345678", 16,
				&PubA, &PubTempA, &PubB, &PubTempB, &hKeyB);
	if(r)
	{
		printf("SDF_GenerateAgreementDataAndKeyWithECC fail:%x\n", r);
		goto err;		
	}

	//A
	r = SDF_GenerateKeyWithECC(hSessionHandle, (u8*)"1234567812345678", 16, &PubB, &PubTempB, hExchA, &hKeyA);
	if(r)
	{
		printf("SDF_GenerateKeyWithECC fail:%x\n", r);
		goto err;		
	}

#if 1
	for(i=0; i<16; i++)
		data[i] = (unsigned char)(i+0x10);	
	datalen = 16;
	
	r = SDF_Encrypt(hSessionHandle, hKeyA, SGD_SM1_ECB, NULL, data, datalen, encdata, &enclen);
	if(r)
	{
		printf("encrypt data fail:%x\n", r);
		return r;
	}
	print_data("encrypt data:", encdata, enclen);

	r = SDF_Decrypt(hSessionHandle, hKeyB, SGD_SM1_ECB, NULL, encdata, enclen, decdata, &declen);
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

	r = SDF_DestroyKey(hSessionHandle, hKeyA);
	if(r)
	{
		printf("destroy session key1 fail:%x\n", r);
		return r;
	}

	r = SDF_DestroyKey(hSessionHandle, hKeyB);
	if(r)
	{
		printf("destroy session key2 fail:%x\n", r);
		return r;
	}	
#endif
	
	printf("%s() - success\n", __func__);
	return 0;
	
err:
	return r;
}

u32 KeyAccessRight_Test(void *hSessionHandle)
{
	u32 r;
	int i;
	ECCSignature sig;
	u8 data[32];
	
	printf("%s()-start\n", __func__);
	for(i=1; i<3; i++)
	{
		r = SDF_ReleasePrivateKeyAccessRight(hSessionHandle, i);
		if(r){
				printf("SDF_ReleasePrivateKeyAccessRight fail:%x\n", r);
				return r;		
		}

		memset(data, 1, 32);
		r = SDF_InternalSign_ECC(hSessionHandle, i, data, 32, &sig);
		if(r == 0)
		{
			printf("release key access right test fail\n");
			return 1;
		}

		r = SDF_GetPrivateKeyAccessRight(hSessionHandle, i, "11111111", 8);
		if(r){
				printf("SDF_GetPrivateKeyAccessRight fail:%x\n", r);
				return r;				
		}

		r = SDF_InternalSign_ECC(hSessionHandle, i, data, 32, &sig);
		if(r)
		{
			printf("get key access right test fail\n");
			return r;
		}
	}	

	for(i=1; i<3; i++)
	{
		r = SDF_GetPrivateKeyAccessRight(hSessionHandle, i, "11111111", 8);
		if(r){
				printf("SDF_GetPrivateKeyAccessRight again fail:%x\n", r);
				return r;				
		}
	}

	r = SDF_ReleasePrivateKeyAccessRight(hSessionHandle, 1);
	if(r){
			printf("SDF_ReleasePrivateKeyAccessRight fail:%x\n", r);
			return r;		
	}

	memset(data, 1, 32);
	r = SDF_InternalSign_ECC(hSessionHandle, 1, data, 32, &sig);
	if(r == 0)
	{
		printf("release key1 access right test fail\n");
		return 1;
	}	

	r = SDF_InternalSign_ECC(hSessionHandle, 2, data, 32, &sig);
	if(r)
	{
		printf("get key2 access right test fail\n");
		return r;
	}
	
	printf("%s() - success\n", __func__);
	return 0;	
}


u32 KeyAccessRight_Manage_Test(void *hSessionHandle)
{
	u32 r;
	int i;
	int MaxRetryCount;
	int RemainRetryCount;

	printf("%s()-start\n", __func__);
	
	for(i=1; i<3; i++)
	{
		r = SDF_ReleasePrivateKeyAccessRight(hSessionHandle, i);
		if(r){
				printf("SDF_ReleasePrivateKeyAccessRight fail:%x\n", r);
				return r;		
		}
	}	


	r = SDF_GetPrivateKeyAccessRight(hSessionHandle, 1, "12345678", 8);
	if(r == 0){
			printf("SDF_GetPrivateKeyAccessRight test fail:%x\n", r);
			return r;				
	}

	r = EVDF_GetPINInfo(hSessionHandle, 1, USER_TYPE, &MaxRetryCount, &RemainRetryCount);
	if(r){
			printf("SDF_GetPINInfo test fail:%x\n", r);
			return r;	
	}
	printf("pin info - MaxRetryCount:%d RemainRetryCount:%d\n", MaxRetryCount, RemainRetryCount);

	r = EVDF_UnlockPIN(hSessionHandle, 1, "11111111", "12345678", &RemainRetryCount);
	if(r){
			printf("SDF_UnlockPIN test fail:%x\n", r);
			return r;	
	}
	printf("unlock pin info - MaxRetryCount:%d\n", RemainRetryCount);

	r = SDF_GetPrivateKeyAccessRight(hSessionHandle, 1, "12345678", 8);
	if(r){
			printf("SDF_GetPrivateKeyAccessRight fail:%x\n", r);
			return r;				
	}

	r = EVDF_ChangePIN(hSessionHandle, 1, USER_TYPE, "12345678", "11111111",&RemainRetryCount);
	if(r){
			printf("SDF_ChangePIN fail:%x\n", r);
			return r;				
	}
	printf("change pin info - MaxRetryCount:%d\n", RemainRetryCount);

	r = SDF_GetPrivateKeyAccessRight(hSessionHandle, i, "11111111", 8);
	if(r){
			printf("SDF_GetPrivateKeyAccessRight again fail:%x\n", r);
			return r;				
	}
	
	printf("%s() - success\n", __func__);
	return 0;	
}

u32 KeySlot_State_Test(void *hSessionHandle)
{
	SlotKeyInfo SlotInfo[SDF_MAX_KEY_INDEX];
	int i;
	u32 r;

	for(i=1; i<=SDF_MAX_KEY_INDEX; i++)
	{
		r = EVDF_GetKeySlotInfo(hSessionHandle, i, &SlotInfo[i-1]);
		if(r){
			printf("SDF_GetKeySlotInfo fail:%x\n", r);
			return r;				
		}
	}


	printf("---------------------------------------------\n");
	for(i=1; i<=SDF_MAX_KEY_INDEX; i++)
	{
		printf("\n******************************\n");
		printf("slot index:%d\n", SlotInfo[i-1].slot_key_index);

		if(SlotInfo[i-1].rsa_sign_key_flag & SGD_SLOT_KEY_EXIST_MASK)
		{
			printf("rsa sign key exist -- key len[%d]\n", SlotInfo[i-1].rsa_sign_key_flag & SDF_ALGO_KEY_LEN_MASK);
		}else{
			printf("rsa sign key non exist\n");
		}

		if(SlotInfo[i-1].rsa_enc_key_flag & SGD_SLOT_KEY_EXIST_MASK)
		{
			printf("rsa enc key exist -- key len[%d]\n", SlotInfo[i-1].rsa_enc_key_flag & SDF_ALGO_KEY_LEN_MASK);
		}else{
			printf("rsa enc key non exist\n");
		}

		if(SlotInfo[i-1].ecc_sign_key_flag & SGD_SLOT_KEY_EXIST_MASK)
		{
			printf("ecc sign key exist -- key len[%d]\n", SlotInfo[i-1].ecc_sign_key_flag & SDF_ALGO_KEY_LEN_MASK);
		}else{
			printf("ecc sign key non exist\n");
		}

		if(SlotInfo[i-1].ecc_enc_key_flag & SGD_SLOT_KEY_EXIST_MASK)
		{
			printf("ecc enc key exist -- key len[%d]\n", SlotInfo[i-1].ecc_enc_key_flag & SDF_ALGO_KEY_LEN_MASK);
		}else{
			printf("ecc enc key non exist\n");
		}			
	}
	printf("---------------------------------------------\n");

	return 0;	
}

u32 Hash_Z_Test2(void *hSessionHandle)
{
	u32 r;	
	unsigned char hash[32];
	u32 hash_len;
	ECCrefPublicKey eccpubkey;
	ECCrefPrivateKey eccprikey;
	ECCSignature sig;
	int i;
	unsigned char data[64];	
	u8 keypair[] = {
		//x
		0x19, 0x79, 0x5d, 0xf7, 0x01, 0xf3, 0x9d, 0x1f, 0xb2, 0x20, 0xc4, 0x5f, 0xa7, 0xfa, 0x4e, 0xbf, 
		0xad, 0xd1, 0x70, 0x25, 0x37, 0xb9, 0x46, 0xcd, 0x3d, 0x48, 0x04, 0xb3, 0x7f, 0xbc, 0x3e, 0xa5,
		//y
		0x2b, 0x2c, 0xee, 0xd6, 0xcc, 0x04, 0x2b, 0x5b, 0xbb, 0x56, 0x8d, 0xed, 0x3b, 0x36, 0x73, 0xf2, 
		0x88, 0xe1, 0x9c, 0xc4, 0x9a, 0xe3, 0xc3, 0x50, 0xd2, 0xb8, 0x09, 0x03, 0xd8, 0x6d, 0x91, 0x2c,
		//d
		0x3f, 0x91, 0x68, 0xe8, 0x6d, 0x2a, 0xac, 0xaa, 0x2c, 0x81, 0xd8, 0xba, 0x24, 0x9b, 0xc9, 0x5a, 
		0x60, 0xe0, 0x47, 0x50, 0xa2, 0xee, 0xaa, 0x63, 0x26, 0x2b, 0x54, 0xc4, 0x75, 0x51, 0xb8, 0xdc
	};
	printf("%s()-start\n", __func__);
	for(i=0; i<64; i++)
		data[i] = i;
	memset(&eccpubkey, 0, sizeof(ECCrefPublicKey));
	memcpy(eccpubkey.x+32, keypair, 32);
	memcpy(eccpubkey.y+32, keypair+32, 32);
	eccpubkey.bits = 256;
	memset(&eccprikey, 0, sizeof(ECCrefPrivateKey));
	memcpy(eccprikey.K+32, keypair+64, 32);
	eccprikey.bits = 256;

	r = SDF_HashInit(hSessionHandle, SGD_SM3, &eccpubkey, "1234567812345678", 16);
	if(r)
	{
		printf("SDF_HashInit fail:%x\n", r);
		return r;
	}
	r = SDF_HashUpdate(hSessionHandle, data, sizeof(data));
	if(r)
	{
		printf("SDF_HashUpdate fail:%x\n", r);
		return r;	
	}

	hash_len = 32;
	r = SDF_HashFinal(hSessionHandle, hash, &hash_len);
	if(r)
	{
		printf("SDF_HashFinal fail:%x\n", r);
		return r;	
	}
	print_data("hash", hash, hash_len);

	r = SDF_ExternalSign_ECC(hSessionHandle, SGD_SM2_1, &eccprikey, hash, 32, &sig);
	if(r)
	{
		printf("external ecc sign fail:%x\n", r);
		return r;
	}	
	print_data("sig r", sig.r, ECCref_MAX_LEN);
	print_data("sig s", sig.s, ECCref_MAX_LEN);
//	LOG_DATA(sig.r, ECCref_MAX_LEN);
//	LOG_DATA(sig.s, ECCref_MAX_LEN);

	r = SDF_ExternalVerify_ECC(hSessionHandle, SGD_SM2_1, &eccpubkey, hash, 32, &sig);
	if(r)
	{
		printf("external ecc verify fail:%x\n", r);
		return r;
	}

	printf("%s() - success\n", __func__);
	return 0;
}

u32 Hash_Z_Test3(void *hSessionHandle)
{
	u32 r;	
	unsigned char hash[32];
	u32 hash_len;
	u32 i;
	struct asymm_ver_str *pstr;
	
	unsigned char data[] = 
	{
		0x30,0x82,0x02,0xFF,0xA0,0x03,0x02,0x01,0x02,0x02,0x08,0x33,
		0x00,0x00,0xD3,0x00,0x00,0x00,0x27,0x30,0x0C,0x06,0x08,0x2A,0x81,0x1C,0xCF,0x55,
		0x01,0x83,0x75,0x05,0x00,0x30,0x44,0x31,0x0B,0x30,0x09,0x06,0x03,0x55,0x04,0x06,
		0x13,0x02,0x43,0x4E,0x31,0x10,0x30,0x0E,0x06,0x03,0x55,0x04,0x0A,0x0C,0x07,0x53,
		0x79,0x62,0x65,0x72,0x4F,0x53,0x31,0x0D,0x30,0x0B,0x06,0x03,0x55,0x04,0x0B,0x0C,
		0x04,0x54,0x65,0x73,0x74,0x31,0x14,0x30,0x12,0x06,0x03,0x55,0x04,0x03,0x0C,0x0B,
		0x43,0x6F,0x6D,0x6D,0x6F,0x6E,0x43,0x41,0x53,0x4D,0x32,0x30,0x1E,0x17,0x0D,0x31,
		0x35,0x31,0x32,0x32,0x39,0x31,0x30,0x31,0x33,0x33,0x37,0x5A,0x17,0x0D,0x32,0x35,
		0x31,0x32,0x32,0x36,0x31,0x30,0x31,0x33,0x33,0x37,0x5A,0x30,0x26,0x31,0x0B,0x30,
		0x09,0x06,0x03,0x55,0x04,0x06,0x13,0x02,0x43,0x4E,0x31,0x17,0x30,0x15,0x06,0x03,
		0x55,0x04,0x03,0x0C,0x0E,0x73,0x73,0x6C,0x74,0x65,0x73,0x74,0x73,0x65,0x72,0x76,
		0x65,0x72,0x32,0x30,0x59,0x30,0x13,0x06,0x07,0x2A,0x86,0x48,0xCE,0x3D,0x02,0x01,
		0x06,0x08,0x2A,0x81,0x1C,0xCF,0x55,0x01,0x82,0x2D,0x03,0x42,0x00,0x04,0x45,0x3F,
		0xCA,0x64,0x5A,0x90,0x4A,0x11,0x20,0xC0,0x2C,0x20,0xD6,0xF9,0x62,0x94,0x6C,0x04,
		0x3A,0x4D,0x0C,0x6A,0xB1,0x77,0xCD,0x41,0x7A,0x4B,0x4C,0xF0,0xA0,0x7C,0x37,0xA3,
		0x7D,0x19,0xC2,0x76,0x73,0x10,0x59,0x85,0xB1,0x03,0x67,0xC8,0x06,0x49,0x74,0xCB,
		0x97,0x97,0xE3,0xB1,0x78,0x01,0xD2,0xDE,0x54,0x85,0x9C,0xA8,0x91,0xBD,0xA3,0x82,
		0x01,0xF5,0x30,0x82,0x01,0xF1,0x30,0x0C,0x06,0x03,0x55,0x1D,0x13,0x04,0x05,0x30,
		0x03,0x01,0x01,0x00,0x30,0x1D,0x06,0x03,0x55,0x1D,0x25,0x04,0x16,0x30,0x14,0x06,
		0x08,0x2B,0x06,0x01,0x05,0x05,0x07,0x03,0x02,0x06,0x08,0x2B,0x06,0x01,0x05,0x05,
		0x07,0x03,0x04,0x30,0x0B,0x06,0x03,0x55,0x1D,0x0F,0x04,0x04,0x03,0x02,0x00,0xC0,
		0x30,0x11,0x06,0x09,0x60,0x86,0x48,0x01,0x86,0xF8,0x42,0x01,0x01,0x04,0x04,0x03,
		0x02,0x00,0x80,0x30,0x1F,0x06,0x03,0x55,0x1D,0x23,0x04,0x18,0x30,0x16,0x80,0x14,
		0x13,0x4A,0x99,0xE6,0x00,0xAE,0x09,0x0F,0x9E,0x7D,0x8B,0x31,0x30,0xF9,0x24,0xC1,
		0x3D,0x8A,0x6B,0xC0,0x30,0x81,0xB2,0x06,0x03,0x55,0x1D,0x1F,0x04,0x81,0xAA,0x30,
		0x81,0xA7,0x30,0x81,0xA4,0xA0,0x81,0xA1,0xA0,0x81,0x9E,0x86,0x81,0x9B,0x6C,0x64,
		0x61,0x70,0x3A,0x2F,0x2F,0x74,0x65,0x73,0x74,0x6C,0x64,0x61,0x70,0x2E,0x73,0x79,
		0x62,0x65,0x72,0x6F,0x73,0x2E,0x63,0x6F,0x6D,0x3A,0x33,0x38,0x39,0x2F,0x43,0x4E,
		0x3D,0x43,0x6F,0x6D,0x6D,0x6F,0x6E,0x43,0x41,0x53,0x4D,0x32,0x2C,0x43,0x4E,0x3D,
		0x43,0x6F,0x6D,0x6D,0x6F,0x6E,0x43,0x41,0x53,0x4D,0x32,0x2C,0x20,0x4F,0x55,0x3D,
		0x43,0x52,0x4C,0x44,0x69,0x73,0x74,0x72,0x69,0x62,0x75,0x74,0x65,0x50,0x6F,0x69,
		0x6E,0x74,0x73,0x2C,0x20,0x43,0x3D,0x43,0x4E,0x3F,0x63,0x65,0x72,0x74,0x69,0x66,
		0x69,0x63,0x61,0x74,0x65,0x52,0x65,0x76,0x6F,0x63,0x61,0x74,0x69,0x6F,0x6E,0x4C,
		0x69,0x73,0x74,0x3F,0x62,0x61,0x73,0x65,0x3F,0x6F,0x62,0x6A,0x65,0x63,0x74,0x63,
		0x6C,0x61,0x73,0x73,0x3D,0x63,0x52,0x4C,0x44,0x69,0x73,0x74,0x72,0x69,0x62,0x75,
		0x74,0x69,0x6F,0x6E,0x50,0x6F,0x69,0x6E,0x74,0x30,0x81,0xAC,0x06,0x08,0x2B,0x06,
		0x01,0x05,0x05,0x07,0x01,0x01,0x04,0x81,0x9F,0x30,0x81,0x9C,0x30,0x81,0x99,0x06,
		0x08,0x2B,0x06,0x01,0x05,0x05,0x07,0x30,0x02,0x86,0x81,0x8C,0x6C,0x64,0x61,0x70,
		0x3A,0x2F,0x2F,0x74,0x65,0x73,0x74,0x6C,0x64,0x61,0x70,0x2E,0x73,0x79,0x62,0x65,
		0x72,0x6F,0x73,0x2E,0x63,0x6F,0x6D,0x3A,0x33,0x38,0x39,0x2F,0x43,0x4E,0x3D,0x43,
		0x6F,0x6D,0x6D,0x6F,0x6E,0x43,0x41,0x53,0x4D,0x32,0x2C,0x43,0x4E,0x3D,0x43,0x6F,
		0x6D,0x6D,0x6F,0x6E,0x43,0x41,0x53,0x4D,0x32,0x2C,0x20,0x53,0x54,0x3D,0x63,0x41,
		0x43,0x65,0x72,0x74,0x69,0x66,0x69,0x63,0x61,0x74,0x65,0x73,0x2C,0x20,0x43,0x3D,
		0x43,0x4E,0x3F,0x63,0x41,0x43,0x65,0x72,0x74,0x69,0x66,0x69,0x63,0x61,0x74,0x65,
		0x3F,0x62,0x61,0x73,0x65,0x3F,0x6F,0x62,0x6A,0x65,0x63,0x74,0x43,0x6C,0x61,0x73,
		0x73,0x3D,0x63,0x65,0x72,0x74,0x69,0x66,0x69,0x63,0x61,0x74,0x69,0x6F,0x6E,0x41,
		0x75,0x74,0x68,0x6F,0x72,0x69,0x74,0x79,0x30,0x1D,0x06,0x03,0x55,0x1D,0x0E,0x04,
		0x16,0x04,0x14,0xAD,0x23,0xAE,0xD9,0xB2,0xAB,0x07,0x7D,0x4D,0xE2,0xF1,0x08,0x63,
		0x52,0x72,0x15,0x21,0x6E,0x3B,0xF8
	};	

	ECCSignature sig = 
	{
		{
			0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
			0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
			0x04,0xB7,0xFC,0x29,0xCE,0x58,0x9D,0x99,0xB9,0x31,0x46,0x7D,0x29,0xE6,0xE8,0xD3,
			0x0B,0x78,0xAC,0x2E,0xC5,0x1B,0xEC,0xF0,0x40,0x18,0xED,0xA5,0xF1,0x69,0xE4,0x9F
		},
		{
			0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
			0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
			0xA5,0xA2,0x52,0x91,0x66,0xE0,0x57,0x54,0xED,0x74,0x46,0x9E,0x60,0x32,0x02,0x30,
			0x58,0xB5,0x8D,0xD7,0x48,0xF0,0x29,0x2E,0x9B,0x3D,0x0E,0x1D,0xE5,0x39,0x62,0x30
		}
	};
	
	ECCrefPublicKey pEccPub = 
	{
		256,
		{	
			0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
			0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
			0xd8,0x4a,0x3f,0x77,0xe5,0xa9,0xac,0xf2,0x4a,0xf6,0x0f,0xc2,0xe8,0xdc,0x67,0x09,
			0x76,0x9d,0xd8,0x22,0xae,0x97,0x9b,0x7e,0xba,0x75,0x43,0xc6,0x63,0xe6,0xfd,0x43
		},

		{
			0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
			0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
			0xf4,0xbb,0xa0,0x44,0xda,0x6d,0x20,0x3a,0x86,0x23,0xf3,0x1f,0x1e,0x89,0xa4,0xdd,
			0x77,0x3c,0xab,0x37,0xa2,0x6e,0xef,0x65,0x80,0x5c,0xba,0xc9,0x16,0xcf,0x50,0x60
		},
	};
	printf("%s()-start\n", __func__);

	r = SDF_HashInit(hSessionHandle, SGD_SM3, &pEccPub, "1234567812345678", 16);
	if(r)
	{
		printf("SDF_HashInit fail:%x\n", r);
		return r;
	}

	r = SDF_HashUpdate(hSessionHandle, data, sizeof(data));
	if(r)
	{
		printf("SDF_HashUpdate fail:%x\n", r);
		return r;	
	}

	hash_len = 32;
	r = SDF_HashFinal(hSessionHandle, hash, &hash_len);
	if(r)
	{
		printf("SDF_HashFinal fail:%x\n", r);
		return r;	
	}	

	r = SDF_ExternalVerify_ECC(hSessionHandle, SGD_SM2_1,  &pEccPub, hash, 32, &sig);
	if(r)
	{
		printf("SDF_ExternalVerify_ECC fail:%x\n", r);
		return r;	
	}
	printf("hash_z standard test success\n");

	
	
	for(i=0;i<9;i++)
	{	
		printf("-------------------------[%d]--------------------------\n",i);
		pstr = &sm2_ver_str[i];	
	
		memcpy(&pEccPub.x[32],pstr->pverpubkey,32);
		memcpy(&pEccPub.y[32],pstr->pverpubkey+32,32);
		memcpy(&sig.r[32],pstr->pversigval,32);
		memcpy(&sig.s[32],pstr->pversigval+32,32);
	     	
	     	r = SDF_HashInit(hSessionHandle, SGD_SM3, &pEccPub, pstr->pverid, 32);
		if(r)
		{
			printf("SDF_HashInit fail:%x\n", r);
			return r;
		}

		r = SDF_HashUpdate(hSessionHandle, pstr->pversrcdat, pstr->len);
		if(r)
		{
			printf("SDF_HashUpdate fail:%x\n", r);
			return r;	
		}

		hash_len = 32;
		r = SDF_HashFinal(hSessionHandle, hash, &hash_len);
		if(r)
		{
			printf("SDF_HashFinal fail:%x\n", r);
			return r;	
		}	

		r = SDF_ExternalVerify_ECC(hSessionHandle, SGD_SM2_1,  &pEccPub, hash, 32, &sig);
		if(r)
		{
			printf("SDF_ExternalVerify_ECC fail:%x\n", r);
			return r;	
		}
		printf("hash_z standard test[%d] success\n",i);
	}
	
	printf("%s() - success\n", __func__);
	return 0;	
}


u32 KEK_Test(void *hSessionHandle)
{
	int r;
	u32 cnt = 0;
	u32 uiKeyBits,uiAlgID,uiKEKIndex;
	u8  ucKey[16] = {0};
	u8  uciv[16] = {0};
        u8  iv[16] = {0};
	u32 uiKeyLength;
	u32 i = 0;
	u32 j = 0;
	void * hKeyHandle_0;
	void * hKeyHandle_1;
	u32 ulAlgID;
	u32 ALGID_ARRAY[4] = {SGD_SM1_ECB, SGD_SM1_CBC, SGD_SMS4_ECB, SGD_SMS4_CBC};

	BYTE *src_data = NULL;
	BYTE *enc_data = NULL;
	BYTE *dec_data = NULL;

	u32 enc_datalen;
	u32 dec_datalen;
	u32 datalen;
	FILE *fp_enc;
	FILE *fp_dec;
	
	//fp_enc = fopen("kek_enc_file", "w+");
	//fp_dec = fopen("kek_dec_file", "w+");
	

	uiKeyBits  = 128;
	uiAlgID = SGD_SM1_ECB;
	uiKEKIndex = 3;

	r = SDF_GenerateKeyWithKEK(hSessionHandle,uiKeyBits,uiAlgID,uiKEKIndex,ucKey,&uiKeyLength,&hKeyHandle_0);
	if(r)
	{
		printf("GenerateKeyWithKEK fail:%x\n", r);
		return r;
	}


	r = SDF_ImportKeyWithKEK(hSessionHandle,uiAlgID,uiKEKIndex,ucKey,uiKeyLength,&hKeyHandle_1);
	if(r)
	{
		printf("ImportKeyWithKEK fail:%x\n", r);
		return r;
	}

	//while(1);
#if 0
	do
	{
		printf("---------------%d---------------\n",cnt++);
		//datalen = rand()%0x100000*16;
		datalen  = 0x8000;
		if(datalen==0)
			datalen = 16;
		printf("datalen = %d\n",datalen);

		src_data = malloc(datalen);
		enc_data = malloc(datalen);
		dec_data = malloc(datalen);

		for(i=0;i<16;i++)
		{
			//iv[i] = rand();
			iv[i] = 0x55;
		}
		
		u32 sector_len = 0x400;
		for(j=0;j<32;j++)
		{
			for(i=0;i<sector_len;i++)
			{
				//src_data[i] = rand();
				src_data[j*0x400+i] = 0x11+j;
			}
		}
		

		for(i=0;i<16;i++)
		{
			uciv[i] = iv[i];
		}
		r = SDF_Encrypt(hSessionHandle,hKeyHandle_0,uiAlgID,uciv,src_data,datalen,enc_data,&enc_datalen);
		if(r)
		{
			printf("Encrypt fail:%x\n", r);
			return r;
		}
		
		fwrite(enc_data, datalen, 1, fp_enc);
		for(i=0;i<16;i++)
		{
			uciv[i] = iv[i];
		}
		r = SDF_Decrypt(hSessionHandle,hKeyHandle_1,uiAlgID,uciv,enc_data,enc_datalen,dec_data,&dec_datalen);
		if(r)
		{
			printf("Decrypt fail:%x\n", r);
			return r;
		}
		fwrite(dec_data, datalen, 1, fp_dec);
		if((dec_datalen != datalen)||(memcmp(dec_data, src_data, datalen)))
		{
			printf("source data != dec data \n");
			return -1;
		}
		else
		{
			printf("%s() - success\n",__func__);	
		}
		//while(1);
	}while(0);
		fclose(fp_enc);
		fclose(fp_dec);
#else
	do
	{
		uiAlgID = ALGID_ARRAY[rand()%0x4];

		printf("---------------%d(id:%x)---------------\n",cnt++, uiAlgID);
		datalen = rand()%0x10000*16;
		//datalen  = 0x20;
		if(datalen==0)
			datalen = 16;
		printf("datalen = %d\n",datalen);

		src_data = malloc(datalen);
		enc_data = malloc(datalen);
		dec_data = malloc(datalen);

		for(i=0;i<16;i++)
		{
			iv[i] = 0x55;
		}
		for(i=0;i<datalen;i++)
		{
			src_data[i] = rand();
			enc_data[i] = 0;
			dec_data[i] = 0;
		}


		for(i=0;i<16;i++)
		{
			uciv[i] = iv[i];
		}
		r = SDF_Encrypt(hSessionHandle,hKeyHandle_0,uiAlgID,uciv,src_data,datalen,enc_data,&enc_datalen);
		if(r)
		{
			printf("Encrypt fail:%x\n", r);
			return r;
		}
		printf("enc_datalen :%x\n", enc_datalen);

		for(i=0;i<16;i++)
		{
			uciv[i] = iv[i];
		}
		r = SDF_Decrypt(hSessionHandle,hKeyHandle_1,uiAlgID,uciv,enc_data,enc_datalen,dec_data,&dec_datalen);
		if(r)
		{
			printf("Decrypt fail:%x\n", r);
			return r;
		}
		printf("dec_datalen :%x\n", dec_datalen);
		if((dec_datalen != datalen)||(memcmp(dec_data, src_data, datalen)))
		{
			printf("source data != dec data \n");

			return -1;
		}
		else
		{
			printf("%s() - success\n",__func__);	

		}
		//while(1);
		free(src_data);
		free(enc_data);
		free(dec_data);
	}while(cnt<0x100);
	
#endif
	r = SDF_DestroyKey(hSessionHandle,hKeyHandle_0);
	if(r)
	{
		printf("destroy session key fail:%x\n", r);
		return r;
	}

	r = SDF_DestroyKey(hSessionHandle,hKeyHandle_1);
	if(r)
	{
		printf("destroy session key fail:%x\n", r);
		return r;
	}
	
	return 0;
}


u32 Sesskey_Random_Test(void * hSessionHandle)
{
	unsigned int r;
	unsigned int i;
	unsigned int keylen;
	unsigned int enclen;
	unsigned char data[16];
	unsigned char encdata[3][16];
	unsigned char key[16];
	void *hKeyHandle[3];

	for(i=0; i<16; i++)
	{
		data[i] = (unsigned char)rand();
	}

	for(i=0; i<3; i++)
	{
		r = SDF_GenerateKeyWithKEK(hSessionHandle, 128, SGD_SM1_ECB, i+1, key, &keylen, &hKeyHandle[i]);
		if(r)
		{
			printf("GenerateKeyWithKEK fail:%x\n", r);
			return r;
		}

		enclen = 16;
		r = SDF_Encrypt(hSessionHandle, hKeyHandle[i], SGD_SM1_ECB, NULL, data, 16, encdata[i], &enclen);
		if(r)
		{
			printf("Encrypt fail:%x\n", r);
			return r;
		}
	}

	for(i=0; i<3; i++)
	{
		r = SDF_DestroyKey(hSessionHandle, hKeyHandle[i]);
		if(r)
		{
			printf("destroy session key fail:%x\n", r);
			return r;
		}
	}

	if((!memcmp(encdata[0], encdata[1], 16)) || (!memcmp(encdata[0], encdata[2], 16)) || (!memcmp(encdata[2], encdata[1], 16)))
	{
		printf("%s()-fail, encdata no difference\n");
		return 1;
	}

	return 0;
}


u32 HASH_Test(void *hSessionHandle)
{
	unsigned int i,r;
	unsigned int data_size;
	BYTE *source_data = NULL;
	BYTE enc_data[100];
	BYTE hash_soft_val[100]={0};
	int sm3_mode;
	u32 enc_len;
	u32 cnt = 0;
	unsigned char *pdata;

	srand((unsigned int)time(NULL));
	do
	{
		cnt++;
		data_size = rand()%0x200000;
		//data_size = cnt;
		if(data_size==0)
		{
			data_size = 100;
		}
//		data_size = 513;
		source_data = malloc(data_size);
		if(source_data==NULL)
		{
			printf("malloc error\n");
		}

		for(i=0; i<data_size; i++)
		{
//			source_data[i] = i;
			source_data[i] = rand();
		}

		sm3_mode = SGD_SM3;

		printf("-------------------------[%d]-----------------------------\n",cnt);
		printf("data_size = %d\n",data_size);
//		if(data_size > 0x4000){
//			pdata = (unsigned char *)&source_data[0x4000];
//			LOG_DATA(source_data, data_size);
//		}
		r = SDF_HashInit(hSessionHandle, sm3_mode, NULL, NULL, 0);
		if(r)
		{
			printf("SDF_HashInit error 0x%x\n", r);
		}

		r = SDF_HashUpdate(hSessionHandle, source_data, data_size);
		if(r)
		{
			printf("SDF_HashUpdate error 0x%x\n", r);
		}

		enc_len = 100;
		r = SDF_HashFinal(hSessionHandle, enc_data , &enc_len);
		if(r)
		{
			printf("SDF_HashFinal error 0x%x\n", r);
		}


		hash_soft_crypto(source_data,hash_soft_val,data_size);

		for(i=0;i<32;i++)
		{
			if(enc_data[i]!=hash_soft_val[i])
			{
				printf("hash error!\n");
				LOG_DATA(enc_data, 32);
				LOG_DATA(hash_soft_val, 32);
				return -1;
			}
		}
		free(source_data);
		printf("hash success!\n");
	}while(cnt<0x40);
	
	printf("%s() - success\n", __func__);
	return r;
}

u32 HASH_Scatter_Test(void *hSessionHandle)
{
	unsigned int i,r;
	unsigned int data_size;
	BYTE *source_data = NULL;
	BYTE enc_data[100];
	BYTE hash_soft_val[100]={0};
	int sm3_mode;
	u32 enc_len;
	u32 cnt = 0;
	u32 dat_offset;

	srand((unsigned int)time(NULL));
	do{
		data_size =  rand()%0x400000;
		if(data_size < 0x1000)
		{
			continue;
		}
		dat_offset = rand()%data_size;
		if(dat_offset < 0x100)
		{
			continue;
		}

		
		source_data = malloc(data_size);
		if(source_data==NULL)
		{
			printf("malloc error\n");
		}

		for(i=0; i<data_size; i++)
		{
			source_data[i] = rand();//i%16;
		}

		sm3_mode = SGD_SM3;

		printf("-------------------------[%d]-----------------------------\n",cnt++);
		printf("data_size = %d\n",data_size);
		printf("dat_offset = %d\n",dat_offset);
		r = SDF_HashInit(hSessionHandle, sm3_mode, NULL, NULL, 0);
		if(r)
		{
			printf("SDF_HashInit error 0x%x\n", r);
		}
		
		r = SDF_HashUpdate(hSessionHandle, source_data, dat_offset);
		if(r)
		{
			printf("SDF_HashUpdate error 0x%x\n", r);
		}
		//printf("test0...\n");
		r = SDF_HashUpdate(hSessionHandle, source_data+dat_offset, data_size-dat_offset);
		if(r)
		{
			printf("SDF_HashUpdate error 0x%x\n", r);
		}
		//printf("test1...\n");

		enc_len = 100;
		r = SDF_HashFinal(hSessionHandle, enc_data , &enc_len);
		if(r)
		{
			printf("SDF_HashFinal error 0x%x\n", r);
		}

		hash_soft_crypto(source_data,hash_soft_val,data_size);

		for(i=0;i<32;i++)
		{
			if(enc_data[i]!=hash_soft_val[i])
			{
				printf("hash error!\n");
				return -1;
			}
		}		
		printf("hash success!\n");

		free(source_data);
	}while(cnt<0x100);
	printf("%s() - success\n", __func__);
	return r;
}

u32 HMAC_Validity_Test(void *hSessionHandle)
{
	unsigned int i,j,r;
	BYTE enc_data[100];
	int enc_len;	
	u8 hmac_key[] = {
		0x11,0x22,0x33,0x44,0x55,0x66,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
		0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	};
	u8 data[] = {
		0x2C,0xB6,0xA0,0x6E,0x92,0xDC,0x95,0x70,0x24,0x2E,0x4E,0x77,0xA1,0x8D,0x6D,0xF0,
		0xBF,0xA1,0x63,0xB7,0x33,0xA6,0x81,0xDF,0xA8,0x6F,0x48,0x65,0x0A,0x25,0x1F,0x76,
	};
	u8 hmac_stdout[]={
		0x17,0xe3,0x2b,0xad,0x10,0x4d,0xeb,0x3e,0xf8,0xfc,0xf4,0xfb,0xa2,0xba,0x92,0xcf,
		0xc5,0x83,0xea,0xc8,0x70,0x9a,0xb8,0x64,0xd9,0xaa,0x6d,0xd8,0xe2,0x15,0xec,0x4c,
	};

	r = EVDF_HMACInit(hSessionHandle, SGD_SM3, hmac_key, 6);
	if(r)
	{
		printf("EVDF_HMACInit error 0x%x\n", r);
	}
	r = EVDF_HMACUpdate(hSessionHandle, data, 32);
	if(r)
	{
		printf("EVDF_HMACUpdate error 0x%x\n", r);
	}

	enc_len = 100;
	r = EVDF_HMACFinal(hSessionHandle, enc_data , &enc_len);
	if(r)
	{
		printf("EVDF_HMACFinal error 0x%x\n", r);
	}
#ifdef LOG
	LOG_DATA(enc_data, enc_len);
#endif
	for(j=0;j<32;j++)
	{
		if(enc_data[j]!=hmac_stdout[j])
		{
			printf("hash mac error!\n");
			return -1;
		}
	}

	
	printf("%s() - success\n", __func__);
	return r;
}

u32 HASH_Validity_Test(void *hSessionHandle)
{
	unsigned int i,j,r;
	unsigned int data_size;
	BYTE *source_data = NULL;
	BYTE enc_data[32];
	int sm3_mode;
	int enc_len;
	

	u8  datlen[5] = {1,8,32,56,96};
	u8 *srcdat[5] = {hash_srcdata0,hash_srcdata1,hash_srcdata2,hash_srcdata3,hash_srcdata4};
	u8 *dstdat[5] = {hash_dstdata0,hash_dstdata1,hash_dstdata2,hash_dstdata3,hash_dstdata4};


	for(i=0;i<5;i++)
	{

		sm3_mode = SGD_SM3;
		data_size = datlen[i];
		//printf("data_size = %d\n",data_size);
		source_data = srcdat[i];
		r = SDF_HashInit(hSessionHandle, sm3_mode, NULL, NULL, 0);
		if(r)
		{
			printf("SDF_HashInit error 0x%x\n", r);
		}

		r = SDF_HashUpdate(hSessionHandle, source_data, data_size);
		if(r)
		{
			printf("SDF_HashUpdate error 0x%x\n", r);
		}

		enc_len = 100;
		r = SDF_HashFinal(hSessionHandle, enc_data , &enc_len);
		if(r)
		{
			printf("SDF_HashFinal error 0x%x\n", r);
		}

		for(j=0;j<32;j++)
		{
			if(enc_data[j]!=dstdat[i][j])
			{
				printf("hash error!\n");
				return -1;
			}
		}
		printf("hash success!\n");
	}
	printf("%s() - success\n", __func__);
	return r;
}

u32 HASH_Key_Test(void *hSessionHandle)
{
	u32 r;
	u32 i = 0;
	u32 j = 0;		
	u8  key[32] = {0};
	void *hKey;	
	unsigned int data_size;
	BYTE *source_data = NULL;
	BYTE *source_data1 = NULL;
	BYTE enc_data[100];
	BYTE hash_soft_val[100]={0};
	int sm3_mode;
	u32 enc_len;
	u32 cnt = 0;
	u32 dat_offset;


	srand((unsigned int)time(NULL));
	for(i=0;i<16;i++)
	{
		key[i] = (u8)rand();
	}

	r = SDF_ImportKey(hSessionHandle, key, 16, &hKey);
	if(r)
	{
		printf("import session key fail:%x\n", r);
		return r;	
	}

	do{
		data_size =  rand()%0x40000;
		if(data_size < 0x100)
		{
			continue;
		}
		dat_offset = rand()%data_size;
		if(dat_offset < 0x80)
		{
			continue;
		}

		
		source_data = malloc(data_size);
		if(source_data==NULL)
		{
			printf("malloc error\n");
		}
		source_data1 = malloc(data_size+0x80);
		if(source_data1==NULL)
		{
			printf("malloc error\n");
		}

		for(i=0; i<data_size; i++)
		{
			source_data[i] = rand();//i%16;
		}

		sm3_mode = SGD_SM3;

		printf("-------------------------[%d]-----------------------------\n",cnt++);
		printf("data_size = %d\n",data_size);
		printf("dat_offset = %d\n",dat_offset);
		r = SDF_HashInit(hSessionHandle, sm3_mode, NULL, NULL, 0);
		if(r)
		{
			printf("SDF_HashInit error 0x%x\n", r);
		}
		
		r = SDF_HashUpdate(hSessionHandle, source_data, dat_offset);
		if(r)
		{
			printf("SDF_HashUpdate error 0x%x\n", r);
		}

		r = EVDF_HashUpdateWithKey(hSessionHandle, hKey, 0);
		if(r)
		{	
			printf("SDF_HashUpdateWithKey error 0x%x\n", r);
		}
		
		//printf("test0...\n");
		r = SDF_HashUpdate(hSessionHandle, source_data+dat_offset, data_size-dat_offset);
		if(r)
		{
			printf("SDF_HashUpdate error 0x%x\n", r);
		}
		//printf("test1...\n");

		enc_len = 100;
		r = SDF_HashFinal(hSessionHandle, enc_data , &enc_len);
		if(r)
		{
			printf("SDF_HashFinal error 0x%x\n", r);
		}

		memcpy(source_data1, source_data, dat_offset);
		memcpy(source_data1+dat_offset, key, 16);
		memcpy(source_data1+dat_offset+16, source_data+dat_offset, data_size-dat_offset);

		hash_soft_crypto(source_data1,hash_soft_val,data_size+16);

		for(i=0;i<32;i++)
		{
			if(enc_data[i]!=hash_soft_val[i])
			{
				printf("hash error!\n");
				return -1;
			}
		}		
		printf("hash success!\n");

		free(source_data);
	}while(cnt<0x100);

	r = SDF_DestroyKey(hSessionHandle, hKey);
	if(r)
	{
		printf("destroy session key1 fail:%x\n", r);
		return r;
	}
	
	printf("%s() - success\n", __func__);
	return r;	
}

u32 HASH_Key_Test2(void *hSessionHandle)
{
	u32 r;
	u32 i = 0;
	u32 j = 0;		
	void *hKey;	
	unsigned int data_size;
	BYTE *source_data = NULL;
	BYTE *source_data1 = NULL;
	BYTE enc_data[100];
	BYTE hash_soft_val[100]={0};
	int sm3_mode;
	u32 enc_len;
	u32 cnt = 0;
	u32 dat_offset;

	unsigned char key[16] ={0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F};
	unsigned char strkey1[] = "000102030405060708090A0B0C0D0E0F";
	unsigned char strkey2[] = "000102030405060708090a0b0c0d0e0f";

	r = SDF_ImportKey(hSessionHandle, key, 16, &hKey);
	if(r)
	{
		printf("import session key fail:%x\n", r);
		return r;	
	}

	do{
		data_size =  rand()%0x40000;
		if(data_size < 0x100)
		{
			continue;
		}
		dat_offset = rand()%data_size;
		if(dat_offset < 0x80)
		{
			continue;
		}

		
		source_data = malloc(data_size);
		if(source_data==NULL)
		{
			printf("malloc error\n");
		}
		source_data1 = malloc(data_size+0x80);
		if(source_data1==NULL)
		{
			printf("malloc error\n");
		}

		for(i=0; i<data_size; i++)
		{
			source_data[i] = rand();//i%16;
		}

		sm3_mode = SGD_SM3;

		printf("-------------------------[%d]-----------------------------\n",cnt++);
		printf("data_size = %d\n",data_size);
		printf("dat_offset = %d\n",dat_offset);
		r = SDF_HashInit(hSessionHandle, sm3_mode, NULL, NULL, 0);
		if(r)
		{
			printf("SDF_HashInit error 0x%x\n", r);
		}
		
		r = SDF_HashUpdate(hSessionHandle, source_data, dat_offset);
		if(r)
		{
			printf("SDF_HashUpdate error 0x%x\n", r);
		}

		r = EVDF_HashUpdateWithKey(hSessionHandle, hKey, 2);
		if(r)
		{	
			printf("SDF_HashUpdateWithKey error 0x%x\n", r);
		}
		
		//printf("test0...\n");
		r = SDF_HashUpdate(hSessionHandle, source_data+dat_offset, data_size-dat_offset);
		if(r)
		{
			printf("SDF_HashUpdate error 0x%x\n", r);
		}
		//printf("test1...\n");

		enc_len = 100;
		r = SDF_HashFinal(hSessionHandle, enc_data , &enc_len);
		if(r)
		{
			printf("SDF_HashFinal error 0x%x\n", r);
		}

		memcpy(source_data1, source_data, dat_offset);
		memcpy(source_data1+dat_offset, strkey2, strlen(strkey2));
		memcpy(source_data1+dat_offset+strlen(strkey2), source_data+dat_offset, data_size-dat_offset);

		hash_soft_crypto(source_data1,hash_soft_val,data_size+strlen(strkey2));

		for(i=0;i<32;i++)
		{
			if(enc_data[i]!=hash_soft_val[i])
			{
				printf("hash error!\n");
				return -1;
			}
		}		
		printf("hash success!\n");

		free(source_data);
	}while(cnt<0x1);


	do{
		data_size =  rand()%0x40000;
		if(data_size < 0x100)
		{
			continue;
		}
		dat_offset = rand()%data_size;
		if(dat_offset < 0x80)
		{
			continue;
		}

		
		source_data = malloc(data_size);
		if(source_data==NULL)
		{
			printf("malloc error\n");
		}
		source_data1 = malloc(data_size+0x80);
		if(source_data1==NULL)
		{
			printf("malloc error\n");
		}

		for(i=0; i<data_size; i++)
		{
			source_data[i] = rand();//i%16;
		}

		sm3_mode = SGD_SM3;

		printf("-------------------------[%d]-----------------------------\n",cnt++);
		printf("data_size = %d\n",data_size);
		printf("dat_offset = %d\n",dat_offset);
		r = SDF_HashInit(hSessionHandle, sm3_mode, NULL, NULL, 0);
		if(r)
		{
			printf("SDF_HashInit error 0x%x\n", r);
		}
		
		r = SDF_HashUpdate(hSessionHandle, source_data, dat_offset);
		if(r)
		{
			printf("SDF_HashUpdate error 0x%x\n", r);
		}

		r = EVDF_HashUpdateWithKey(hSessionHandle, hKey, 3);
		if(r)
		{	
			printf("SDF_HashUpdateWithKey error 0x%x\n", r);
		}
		
		//printf("test0...\n");
		r = SDF_HashUpdate(hSessionHandle, source_data+dat_offset, data_size-dat_offset);
		if(r)
		{
			printf("SDF_HashUpdate error 0x%x\n", r);
		}
		//printf("test1...\n");

		enc_len = 100;
		r = SDF_HashFinal(hSessionHandle, enc_data , &enc_len);
		if(r)
		{
			printf("SDF_HashFinal error 0x%x\n", r);
		}

		memcpy(source_data1, source_data, dat_offset);
		memcpy(source_data1+dat_offset, strkey1, strlen(strkey1));
		memcpy(source_data1+dat_offset+strlen(strkey1), source_data+dat_offset, data_size-dat_offset);

		hash_soft_crypto(source_data1,hash_soft_val,data_size+strlen(strkey1));

		for(i=0;i<32;i++)
		{
			if(enc_data[i]!=hash_soft_val[i])
			{
				printf("hash error!\n");
				return -1;
			}
		}		
		printf("hash success!\n");

		free(source_data);
	}while(cnt<0x1);



	r = SDF_DestroyKey(hSessionHandle, hKey);
	if(r)
	{
		printf("destroy session key1 fail:%x\n", r);
		return r;
	}
	
	printf("%s() - success\n", __func__);
	return r;	
}

u32 HASH_Key_Test3(void *hSessionHandle)
{
	u32 r;
	u32 i = 0;
	u32 j = 0;		
	void *hKey;	
	unsigned int data_size;
	BYTE *source_data = NULL;
	BYTE *source_data1 = NULL;
	BYTE enc_data[100];
	BYTE hash_soft_val[100]={0};
	int sm3_mode;
	u32 enc_len;
	u32 cnt = 0;
	u32 dat_offset;
	unsigned char key[16] ={0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F};
	unsigned char base64[] = "AAECAwQFBgcICQoLDA0ODw==";

	srand((unsigned int)time(NULL));


	r = SDF_ImportKey(hSessionHandle, key, 16, &hKey);
	if(r)
	{
		printf("import session key fail:%x\n", r);
		return r;	
	}

	do{
		data_size =  rand()%0x40000;
		if(data_size < 0x100)
		{
			continue;
		}
		dat_offset = rand()%data_size;
		if(dat_offset < 0x80)
		{
			continue;
		}

		
		source_data = malloc(data_size);
		if(source_data==NULL)
		{
			printf("malloc error\n");
		}
		source_data1 = malloc(data_size+0x80);
		if(source_data1==NULL)
		{
			printf("malloc error\n");
		}

		for(i=0; i<data_size; i++)
		{
			source_data[i] = rand();//i%16;
		}

		sm3_mode = SGD_SM3;

		printf("-------------------------[%d]-----------------------------\n",cnt++);
		printf("data_size = %d\n",data_size);
		printf("dat_offset = %d\n",dat_offset);
		r = SDF_HashInit(hSessionHandle, sm3_mode, NULL, NULL, 0);
		if(r)
		{
			printf("SDF_HashInit error 0x%x\n", r);
		}
		
		r = SDF_HashUpdate(hSessionHandle, source_data, dat_offset);
		if(r)
		{
			printf("SDF_HashUpdate error 0x%x\n", r);
		}

		r = EVDF_HashUpdateWithKey(hSessionHandle, hKey, 1);
		if(r)
		{	
			printf("SDF_HashUpdateWithKey error 0x%x\n", r);
		}
		
		//printf("test0...\n");
		r = SDF_HashUpdate(hSessionHandle, source_data+dat_offset, data_size-dat_offset);
		if(r)
		{
			printf("SDF_HashUpdate error 0x%x\n", r);
		}
		//printf("test1...\n");

		enc_len = 100;
		r = SDF_HashFinal(hSessionHandle, enc_data , &enc_len);
		if(r)
		{
			printf("SDF_HashFinal error 0x%x\n", r);
		}
		print_data("hash", enc_data, enc_len);

		memcpy(source_data1, source_data, dat_offset);
		memcpy(source_data1+dat_offset, base64, strlen(base64));
		memcpy(source_data1+dat_offset+strlen(base64), source_data+dat_offset, data_size-dat_offset);

		hash_soft_crypto(source_data1,hash_soft_val,data_size+strlen(base64));

		for(i=0;i<32;i++)
		{
			if(enc_data[i]!=hash_soft_val[i])
			{
				printf("hash error!\n");
				return -1;
			}
		}	
		
		printf("hash success!\n");

		free(source_data);
	}while(cnt<0x1);

	r = SDF_DestroyKey(hSessionHandle, hKey);
	if(r)
	{
		printf("destroy session key1 fail:%x\n", r);
		return r;
	}
	
	printf("%s() - success\n", __func__);
	return r;	
}



u32 RSA_ExternalKey_Test(void *hSessionHandle)
{
	u32 r;
	RSArefPublicKey rsapubkey;
	RSArefPrivateKey rsaprikey;
	int i;
	unsigned char data[256];
	unsigned char encdata[256];
	unsigned char decdata[256];
	unsigned int datalen;
	unsigned int enclen;
	unsigned int declen;

	printf("%s()-start\n", __func__);

	rsapubkey.bits = 2048;
	memcpy(rsapubkey.m, rsa_keypair_2048, RSAref_MAX_LEN);
	c_reverse(rsapubkey.m, RSAref_MAX_LEN);	
	rsaprikey.bits = 2048;
	memcpy(rsaprikey.m, rsa_keypair_2048, RSAref_MAX_LEN);
	c_reverse(rsaprikey.m, RSAref_MAX_LEN);	
	memcpy(rsaprikey.prime[0], rsa_keypair_2048+RSAref_MAX_PLEN*2, RSAref_MAX_PLEN);
	c_reverse(rsaprikey.prime[0], RSAref_MAX_LEN/2);
	memcpy(rsaprikey.prime[1], rsa_keypair_2048+RSAref_MAX_PLEN*3, RSAref_MAX_PLEN);
	c_reverse(rsaprikey.prime[1], RSAref_MAX_LEN/2);	
	memcpy(rsaprikey.pexp[0], rsa_keypair_2048+RSAref_MAX_PLEN*4, RSAref_MAX_PLEN);
	c_reverse(rsaprikey.pexp[0], RSAref_MAX_LEN/2);
	memcpy(rsaprikey.pexp[1], rsa_keypair_2048+RSAref_MAX_PLEN*5, RSAref_MAX_PLEN);
	c_reverse(rsaprikey.pexp[1], RSAref_MAX_LEN/2);
	memcpy(rsaprikey.coef, rsa_keypair_2048+RSAref_MAX_PLEN*6, RSAref_MAX_PLEN);
	c_reverse(rsaprikey.coef, RSAref_MAX_LEN/2);
	memcpy(rsaprikey.d, rsa_keypair_2048+RSAref_MAX_PLEN*7, RSAref_MAX_LEN);
	c_reverse(rsaprikey.d, RSAref_MAX_LEN);

	datalen = 256;
	enclen = 256;
	for(i=0; i<datalen; i++)
		data[i] = (u8)(i+0xa0);
	r = SDF_ExternalPublicKeyOperation_RSA(hSessionHandle, &rsapubkey, data, datalen, encdata, &enclen);
	if(r)
	{
		printf("external rsa public key operation fail:%x\n", r);
		return r;
	}

	declen = 256;
	r = SDF_ExternalPrivateKeyOperation_RSA(hSessionHandle, &rsaprikey, encdata, enclen, decdata, &declen);
	if(r)
	{
		printf("external rsa private key operation fail:%x\n", r);
		return r;
	}
	if((declen != datalen) || memcmp(data, decdata, datalen))
	{
		printf("%s()-source data != dec data\n", __func__);
		return 1;
	}

	printf("%s() - success\n", __func__);
	return 0;
}


u32 ECC_ExternalKey_Test1(void *hSessionHandle)
{
	u32 r;
	ECCrefPublicKey eccpubkey;
	ECCrefPrivateKey eccprikey;
	ECCSignature sig;
	int i;
	unsigned char data[32];	
	u8 keypair[] = {
		//x
		0x19, 0x79, 0x5d, 0xf7, 0x01, 0xf3, 0x9d, 0x1f, 0xb2, 0x20, 0xc4, 0x5f, 0xa7, 0xfa, 0x4e, 0xbf, 
		0xad, 0xd1, 0x70, 0x25, 0x37, 0xb9, 0x46, 0xcd, 0x3d, 0x48, 0x04, 0xb3, 0x7f, 0xbc, 0x3e, 0xa5,
		//y
		0x2b, 0x2c, 0xee, 0xd6, 0xcc, 0x04, 0x2b, 0x5b, 0xbb, 0x56, 0x8d, 0xed, 0x3b, 0x36, 0x73, 0xf2, 
		0x88, 0xe1, 0x9c, 0xc4, 0x9a, 0xe3, 0xc3, 0x50, 0xd2, 0xb8, 0x09, 0x03, 0xd8, 0x6d, 0x91, 0x2c,
		//d
		0x3f, 0x91, 0x68, 0xe8, 0x6d, 0x2a, 0xac, 0xaa, 0x2c, 0x81, 0xd8, 0xba, 0x24, 0x9b, 0xc9, 0x5a, 
		0x60, 0xe0, 0x47, 0x50, 0xa2, 0xee, 0xaa, 0x63, 0x26, 0x2b, 0x54, 0xc4, 0x75, 0x51, 0xb8, 0xdc
	};

	printf("%s()-start\n", __func__);

	for(i=0; i<32; i++)
		data[i] = (u8)(i+0x80);

	memset(&eccprikey, 0, sizeof(ECCrefPrivateKey));
	memcpy(eccprikey.K+32, keypair+64, 32);
	eccprikey.bits = 256;
	r = SDF_ExternalSign_ECC(hSessionHandle, SGD_SM2_1, &eccprikey, data, 32, &sig);
	if(r)
	{
		printf("external ecc sign fail:%x\n", r);
		return r;
	}	

	memset(&eccpubkey, 0, sizeof(ECCrefPublicKey));
	memcpy(eccpubkey.x+32, keypair, 32);
	memcpy(eccpubkey.y+32, keypair+32, 32);
	eccpubkey.bits = 256;
	r = SDF_ExternalVerify_ECC(hSessionHandle, SGD_SM2_1, &eccpubkey, data, 32, &sig);
	if(r)
	{
		printf("external ecc verify fail:%x\n", r);
		return r;
	}
	
	printf("%s() - success\n", __func__);
	return 0;	
}

u32 ECC_ExternalKey_Test2(void *hSessionHandle)
{
	u32 r;
	ECCrefPublicKey eccpubkey;
	ECCrefPrivateKey eccprikey;
	int i;
	unsigned char data[32];
	unsigned char encdata[256];
	unsigned char decdata[256];
	int declen;
	ECCCipher *pecccipher = (ECCCipher *)encdata;	

	u8 keypair[] = {
		//x
		0x19, 0x79, 0x5d, 0xf7, 0x01, 0xf3, 0x9d, 0x1f, 0xb2, 0x20, 0xc4, 0x5f, 0xa7, 0xfa, 0x4e, 0xbf, 
		0xad, 0xd1, 0x70, 0x25, 0x37, 0xb9, 0x46, 0xcd, 0x3d, 0x48, 0x04, 0xb3, 0x7f, 0xbc, 0x3e, 0xa5,
		//y
		0x2b, 0x2c, 0xee, 0xd6, 0xcc, 0x04, 0x2b, 0x5b, 0xbb, 0x56, 0x8d, 0xed, 0x3b, 0x36, 0x73, 0xf2, 
		0x88, 0xe1, 0x9c, 0xc4, 0x9a, 0xe3, 0xc3, 0x50, 0xd2, 0xb8, 0x09, 0x03, 0xd8, 0x6d, 0x91, 0x2c,
		//d
		0x3f, 0x91, 0x68, 0xe8, 0x6d, 0x2a, 0xac, 0xaa, 0x2c, 0x81, 0xd8, 0xba, 0x24, 0x9b, 0xc9, 0x5a, 
		0x60, 0xe0, 0x47, 0x50, 0xa2, 0xee, 0xaa, 0x63, 0x26, 0x2b, 0x54, 0xc4, 0x75, 0x51, 0xb8, 0xdc
	};

	printf("%s()-start\n", __func__);

	/*  test enternal ecc  */
	printf("%s()-test external ecc encrypt\n", __func__);
	memset(&eccpubkey, 0, sizeof(ECCrefPublicKey));
	memcpy(eccpubkey.x+32, keypair, 32);
	memcpy(eccpubkey.y+32, keypair+32, 32);
	eccpubkey.bits = 256;
	memset(data, 2, 32);
	r = SDF_ExternalEncrypt_ECC(hSessionHandle, SGD_SM2_3, &eccpubkey, data, 32, pecccipher);
	if(r)
	{
		printf("external ecc encrypt fail:%x\n", r);
		return r;
	}
#ifdef LOG	
	LOG_DATA(pecccipher->C, pecccipher->L);
#endif

	memset(&eccprikey, 0, sizeof(ECCrefPrivateKey));
	memcpy(eccprikey.K+32, keypair+64, 32);
	eccprikey.bits = 256;
	declen = 256;
	r = SDF_ExternalDecrypt_ECC(hSessionHandle, SGD_SM2_3, &eccprikey, pecccipher, decdata, &declen);
	if(r)
	{
		printf("external ecc decrypt fail:%x\n", r);
		return r;			
	}
#ifdef LOG	
	LOG_DATA(decdata, declen);
#endif
	if((declen != 32) || memcmp(data, decdata, 32))
	{
		printf("%s()-source data != dec data\n", __func__);
		return 1;
	}
	printf("test ecc external encrypt success\n");

	printf("%s() - success\n", __func__);
	return 0;
}


u32 ECC_InternalKey_Test1(void *hSessionHandle)
{
	u32 r;
	int i;
	ECCCipher *pecccipher;
	unsigned char encdata[256] = {0};
	unsigned char decdata[256] = {0};
	int declen;
	unsigned char srcdata[] = {0x55,0x45,0x33,0x23,0x49,0xCD,0x1F,0x10,0x66,0x86,0x73,0x2A,0xE4,0xE8,0x6B,0x7E,
		0x7E,0xA0,0x89,0xEC,0x21,0x9D,0x59,0x4F,0x49,0xCE,0xEA,0x2A,0x6A,0x93,0x00,0xEC};

	printf("%s()-start\n", __func__);
	for(i=1; i<=4; i++)
	{
		pecccipher = (ECCCipher *)encdata;	
		memset(pecccipher, 0, sizeof(ECCCipher));

		r = SDF_InternalEncrypt_ECC(hSessionHandle, i, srcdata, 32, pecccipher);
		if(r)
		{
			printf("internal ecc encrypt fail:%x\n", r);
			return r;			
		}
#ifdef LOG		
		printf("%s()-pecccipher->L:%d\n", __func__, pecccipher->L);
		LOG_DATA(pecccipher->C, pecccipher->L);
#endif
		declen = 256;
		memset(decdata, 0x00, 256);
		r = SDF_InternalDecrypt_ECC(hSessionHandle, i, pecccipher, decdata, &declen);
		if(r)
		{
			printf("internal ecc decrypt fail:%x\n", r);
			return r;			
		}
#ifdef LOG		
		printf("%s()-declen:%d\n", __func__, declen);
		LOG_DATA(decdata, declen);
#endif		
		if((declen != 32) || memcmp(srcdata, decdata, 32))
		{
			printf("%s()-source data != dec data\n", __func__);
			return 1;
		}
	}

	printf("%s() - success\n", __func__);
	return 0;	
}

u32 ECC_InternalKey_Test2(void *hSessionHandle)
{
	u32 r;
	ECCCipher *pecccipher;
	struct asymm_dec_str *pstr;

	unsigned char encdata[256] = {0};
	unsigned char decdata[256] = {0};
	int declen;
	unsigned int stddatalen;

	pstr = &sm2_dec_str[0];
	stddatalen = pstr->len;

	pecccipher = (ECCCipher *)encdata;	
	memset(pecccipher, 0, sizeof(ECCCipher));
	pecccipher->L = stddatalen;
	memcpy(pecccipher->x+32, pstr->psrcdat, 32);
	memcpy(pecccipher->y+32, pstr->psrcdat+32, 32);
	memcpy(pecccipher->M, pstr->psrcdat+64+pecccipher->L, 32);
	memcpy(pecccipher->C, pstr->psrcdat+64, pecccipher->L);

	declen = 256;
	r = SDF_InternalDecrypt_ECC(hSessionHandle, SDF_MAX_KEY_INDEX-1, pecccipher, decdata, &declen);
	if(r)
	{
		printf("internal ecc decrypt fail:%x\n", r);
		return r;			
	}
	LOG_DATA(decdata, declen);
	if((declen != stddatalen) || memcmp(pstr->pstddat, decdata, stddatalen))
	{
		printf("%s()-source data != dec data\n", __func__);
		return 1;
	}	

	printf("%s() - success\n", __func__);
	return 0;
}

u32 ECC_InternalKey_Test3(void *hSessionHandle)
{
	u32 r;
	int i;
	ECCCipher *pecccipher;
	unsigned char encdata[256] = {0};
	unsigned char decdata[256] = {0};
	int declen;
	unsigned char srcdata[] = {0x55,0x45,0x33,0x23,0x49,0xCD,0x1F,0x10,0x66,0x86,0x73,0x2A,0xE4,0xE8,0x6B,0x7E,
		0x7E,0xA0,0x89,0xEC,0x21,0x9D,0x59,0x4F,0x49,0xCE,0xEA,0x2A,0x6A,0x93,0x00,0xEC};

	printf("%s()-start\n", __func__);
	for(i=1; i<=4; i++)
	{
		pecccipher = (ECCCipher *)encdata;	
		memset(pecccipher, 0, sizeof(ECCCipher));

		r = EVDF_InternalECCEncrypt(hSessionHandle, i, SGD_SM2_1, srcdata, 32, pecccipher);
		if(r)
		{
			printf("internal ecc encrypt fail:%x\n", r);
			return r;			
		}
#ifdef LOG		
		printf("%s()-pecccipher->L:%d\n", __func__, pecccipher->L);
		LOG_DATA(pecccipher->C, pecccipher->L);
#endif
		declen = 256;
		memset(decdata, 0x00, 256);
		r = EVDF_InternalECCDecrypt(hSessionHandle, i, SGD_SM2_1, pecccipher, decdata, &declen);
		if(r)
		{
			printf("internal ecc decrypt fail:%x\n", r);
			return r;			
		}
#ifdef LOG		
		printf("%s()-declen:%d\n", __func__, declen);
		LOG_DATA(decdata, declen);
#endif		
		if((declen != 32) || memcmp(srcdata, decdata, 32))
		{
			printf("%s()-source data != dec data\n", __func__);
			return 1;
		}
	}

	for(i=1; i<=4; i++)
	{
		pecccipher = (ECCCipher *)encdata;	
		memset(pecccipher, 0, sizeof(ECCCipher));

		r = EVDF_InternalECCEncrypt(hSessionHandle, i, SGD_SM2_3, srcdata, 32, pecccipher);
		if(r)
		{
			printf("internal ecc encrypt fail:%x\n", r);
			return r;			
		}
#ifdef LOG		
		printf("%s()-pecccipher->L:%d\n", __func__, pecccipher->L);
		LOG_DATA(pecccipher->C, pecccipher->L);
#endif
		declen = 256;
		memset(decdata, 0x00, 256);
		r = EVDF_InternalECCDecrypt(hSessionHandle, i, SGD_SM2_3, pecccipher, decdata, &declen);
		if(r)
		{
			printf("internal ecc decrypt fail:%x\n", r);
			return r;			
		}
#ifdef LOG		
		printf("%s()-declen:%d\n", __func__, declen);
		LOG_DATA(decdata, declen);
#endif		
		if((declen != 32) || memcmp(srcdata, decdata, 32))
		{
			printf("%s()-source data != dec data\n", __func__);
			return 1;
		}
	}

	printf("%s() - success\n", __func__);
	return 0;	
}


u32 Asymm_Validity_Test(void *hSessionHandle)
{
	u32 r;
	ECCrefPublicKey eccpubkey;
	ECCrefPrivateKey eccprikey;
	ECCCipher *pecccipher;
	
	int i;
	struct asymm_dec_str *pstr;
	
	unsigned char encdata[256] = {0};
	unsigned char decdata[256] = {0};
	unsigned char sigdata[256] = {0};
	int declen;
	unsigned int stddatalen;

	for(i=0;i<11;i++)
	{
		pstr = &sm2_dec_str[i];
		stddatalen = pstr->len;

		pecccipher = (ECCCipher *)encdata;	
		memset(pecccipher, 0, sizeof(ECCCipher));
		pecccipher->L = stddatalen;
		memcpy(pecccipher->x+32, pstr->psrcdat, 32);
		memcpy(pecccipher->y+32, pstr->psrcdat+32, 32);
		memcpy(pecccipher->M, pstr->psrcdat+64+pecccipher->L, 32);
		memcpy(pecccipher->C, pstr->psrcdat+64, pecccipher->L);

		printf("--------------[%d]----------------\n", i);
		printf("%s()-start\n", __func__);

		declen = 256;
		memset(&eccprikey, 0, sizeof(ECCrefPrivateKey));
		memcpy(eccprikey.K+32, pstr->pkey+64, 32);
		eccprikey.bits = 256;
		r = SDF_ExternalDecrypt_ECC(hSessionHandle, SGD_SM2_3, &eccprikey, pecccipher, decdata, &declen);
		if(r)
		{
			printf("external ecc decrypt fail:%x\n", r);
			return r;			
		}
		//LOG_DATA(decdata, declen);
		if((declen != stddatalen) || memcmp(pstr->pstddat, decdata, stddatalen))
		{
			printf("%s()-source data != dec data\n", __func__);
			return 1;
		}
		//printf("test ecc external encrypt success\n");
	}

	printf("%s() - success\n", __func__);
	return 0;
}

u32 MAC_Test(void *hSessionHandle)
{
	int r;
	u32 uiKeyBits,uiAlgID,uiKEKIndex;
	u8  ucKey[16] = {0};
	u8  uciv[16] = {0};
	u8  iv[16] = {0};
	u8  data_last[16] = {0};
	u32 uiKeyLength;
	u32 i = 0;
	void * hKeyHandle_0;
	void * hKeyHandle_1;
	u32 ulAlgID;
	

	BYTE *src_data = NULL;
	BYTE *enc_data = NULL;
	BYTE *mac_data = NULL;

	u32 enc_datalen;
	u32 mac_datalen;
	u32 datalen;

	uiKeyBits  = 128;
	uiAlgID = SGD_SM1_ECB;
	uiKEKIndex = 0x00000001;
	
	r = SDF_GenerateKeyWithKEK(hSessionHandle,uiKeyBits,uiAlgID,uiKEKIndex,ucKey,&uiKeyLength,&hKeyHandle_0);
	if(r)
	{
		printf("GenerateKeyWithKEK fail:%x\n", r);
		return r;
	}

	r = SDF_ImportKeyWithKEK(hSessionHandle,uiAlgID,uiKEKIndex,ucKey,uiKeyLength,&hKeyHandle_1);
	if(r)
	{
		printf("ImportKeyWithKEK fail:%x\n", r);
		return r;
	}

	do
	{
		//<=29K
		datalen = rand()%0x700*16;
		//datalen = 512;
		if(datalen==0)
			datalen = 16;
		printf("datalen = %d\n",datalen);
		src_data = malloc(datalen);
		enc_data = malloc(datalen);
		mac_data = malloc(datalen);

		for(i=0;i<16;i++)
		{
			iv[i] = rand();
		}
		for(i=0;i<datalen;i++)
		{
			src_data[i] = rand();
		}

		for(i=0;i<16;i++)
		{
			uciv[i] = iv[i];
		}
		uiAlgID = SGD_SM1_CBC;
		r = SDF_Encrypt(hSessionHandle,hKeyHandle_0,uiAlgID,uciv,src_data,datalen,enc_data,&enc_datalen);
		if(r)
		{
			printf("Encrypt fail:%x\n", r);
			return r;
		}

		memcpy(data_last,enc_data+enc_datalen-16,16);
		print_data("data last:", data_last, 16);
		//printf("enc ok ...\n");

		for(i=0;i<16;i++)
		{
			uciv[i] = iv[i];
		}
		uiAlgID = SGD_SM1_MAC;
		r = SDF_CalculateMAC(hSessionHandle,hKeyHandle_1,uiAlgID,uciv,src_data,datalen,mac_data,&mac_datalen);
		if(r)
		{
			printf("CalculateMac fail:%x\n", r);
			return r;
		}

		print_data("mac data:", mac_data, 16);
		if((memcmp(mac_data, data_last, 16)))
		{
			printf("source data != dec data \n");
			return -1;
		}
		else
		{
			printf("%s() - success\n",__func__);
		}
		//while(1);
		free(src_data);
		free(enc_data);
		free(mac_data);
	}while(0);

	r = SDF_DestroyKey(hSessionHandle, hKeyHandle_0);
	if(r)
	{
		printf("destroy session key1 fail:%x\n", r);
		return r;
	} 

	r = SDF_DestroyKey(hSessionHandle, hKeyHandle_1);
	if(r)
	{
		printf("destroy session key1 fail:%x\n", r);
		return r;
	} 
	
	return 0;
}

u32 MAC_Standard_Test(void *hSessionHandle)
{
	int r;
	u8  mac_data[16] = {0};
	u8  las_data[16] = {0};
	u8 tempIV[16];
	u32 i = 0;
	void * hKeyHandle;
	u32 uiAlgID;

	u32 mac_datalen;
	u32 datalen;
	struct symm_str *pstr;

	//uiAlgID = SGD_SM1_MAC;
	uiAlgID = SGD_SMS4_MAC;
	//uiAlgID = SGD_SSF33_MAC;

	for(i=0;i<5;i++)
	{
		switch(uiAlgID)
		{
			case SGD_SM1_MAC:  pstr = &sm1_cbc_enc_str[i];  break;
			case SGD_SMS4_MAC: pstr = &sms4_cbc_enc_str[i]; break;
			case SGD_SSF33_MAC:pstr = &ssf33_cbc_enc_str[i];break;
			default:printf("uiAlgID error!\n");return -1;
		}
		
		r = SDF_ImportKey(hSessionHandle, pstr->pkey, 16, &hKeyHandle);
		if(r)
		{
			printf("import session key fail:%x\n", r);
			return r;	
		}

		if(pstr->piv)
			memcpy(tempIV, pstr->piv, 16);
		r = SDF_CalculateMAC(hSessionHandle,hKeyHandle,uiAlgID,tempIV,pstr->psrcdat,pstr->len,mac_data,&mac_datalen);
		if(r)
		{
			printf("CalculateMac fail:%x\n", r);
			return r;
		}
		print_data("mac data:", mac_data, 16);

		r = SDF_DestroyKey(hSessionHandle, hKeyHandle);
		if(r)
		{
			printf("destroy session key1 fail:%x\n", r);
			return r;
		} 
		
		memcpy(las_data,pstr->pdstdat+pstr->len-16,16);
		//print_data("las data:", las_data, 16);
		if((memcmp(mac_data, las_data, 16)))
		{
			printf("source data != dec data \n");
			return -1;
		}
		else
		{
			printf("%s() - success[%d]\n",__func__,i);
		}

	}
	//while(1);

	return 0;
}


u32 ImportKey_SessionKey_Test(void *hSessionHandle)
{
	u32 r;
	void *hKey1;
	void *hKey2;
	void *hKey3;
	unsigned char data[16];
	unsigned char encdata[16];
	unsigned char decdata[16];
	unsigned int datalen;
	unsigned int enclen;
	unsigned int declen;	
	int i;	
	u8  key1[32] = {0};
	u8  key2[32] = {0};
	u8  key3[32] = {0};
	unsigned int key3_len;

	printf("%s()-start\n", __func__);

	srand((unsigned int)time(NULL));
	for(i=0;i<16;i++)
	{
		key1[i] = (u8)rand();
		key2[i] = (u8)rand();
	}

	r = SDF_ImportKey(hSessionHandle, key1, 16, &hKey1);
	if(r)
	{
		printf("import session key fail:%x\n", r);
		return r;	
	}	

	r = SDF_ImportKey(hSessionHandle, key2, 16, &hKey2);
	if(r)
	{
		printf("import session key fail:%x\n", r);
		return r;	
	}

	r = SDF_Encrypt(hSessionHandle, hKey1, SGD_SM1_ECB, NULL, key2, 16, key3, &key3_len);
	if(r)
	{
		printf("encrypt data fail:%x\n", r);
		return r;
	}
#ifdef LOG	
	print_data("key3 encrypt data:", key3, key3_len);
#endif	

	r = EVDF_ImportKeyWithSessionKey(hSessionHandle, SGD_SM1_ECB, hKey1, key3, key3_len, &hKey3);
	if(r)
	{
		printf("import key with session key fail:%x\n", r);
		return r;
	}


	for(i=0; i<16; i++)
		data[i] = (unsigned char)(i+0x10);	
	datalen = 16;
	
	r = SDF_Encrypt(hSessionHandle, hKey2, SGD_SM1_ECB, NULL, data, datalen, encdata, &enclen);
	if(r)
	{
		printf("encrypt data fail:%x\n", r);
		return r;
	}
#ifdef LOG	
	print_data("encrypt data:", encdata, enclen);
#endif

	r = SDF_Decrypt(hSessionHandle, hKey3, SGD_SM1_ECB, NULL, encdata, enclen, decdata, &declen);
	if(r)
	{
		printf("decrypt data fail:%x\n", r);
		return r;		
	}
#ifdef LOG	
	print_data("decrypt data:", decdata, declen);
#endif

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

	r = SDF_DestroyKey(hSessionHandle, hKey3);
	if(r)
	{
		printf("destroy session key2 fail:%x\n", r);
		return r;
	}	

	printf("%s() - success\n", __func__);
	return 0;	

}

u32 ImportKey_Test(void *hSessionHandle)
{
	u32 r;	
	void *hKey;
	unsigned char data[16];
	unsigned char encdata[16];
	unsigned char decdata[16];
	unsigned int datalen;
	unsigned int enclen;
	unsigned int declen;	
	int i;
	unsigned char key[16];
	u32 ALGID_ARRAY[4] = {SGD_SM1_ECB, SGD_SM1_CBC, SGD_SMS4_ECB, SGD_SMS4_CBC};
	u32 cnt = 0;

	u32 uiAlgID;
	u8  ucKey[16] = {0};
	u8  uciv[16] = {0};
        u8  iv[16] = {0};
	u32 uiKeyLength;
	u32 ulAlgID;
	BYTE *src_data = NULL;
	BYTE *enc_data = NULL;
	BYTE *dec_data = NULL;
	u32 enc_datalen;
	u32 dec_datalen;	


	printf("%s() -start\n", __func__);
#if 0
	for(i=0; i<16; i++)
		key[i] = (u8)(i);
	r = SDF_ImportKey(hSessionHandle, key, 16, &hKey);
	if(r)
	{
		printf("import session key fail:%x\n", r);
		return r;	
	}

	for(i=0; i<16; i++)
		data[i] = (unsigned char)(i+0x20);	
	datalen = 16;
#if 1	
	r = SDF_Encrypt(hSessionHandle, hKey, SGD_SM1_ECB, NULL, data, datalen, encdata, &enclen);
	if(r)
	{
		printf("encrypt data fail:%x\n", r);
		return r;
	}
	print_data("encrypt data:", encdata, enclen);

	r = SDF_Decrypt(hSessionHandle, hKey, SGD_SM1_ECB, NULL, encdata, enclen, decdata, &declen);
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
#endif	
	r = SDF_DestroyKey(hSessionHandle, hKey);
	if(r)
	{
		printf("destroy session key1 fail:%x\n", r);
		return r;
	} 
#else

	for(i=0; i<16; i++)
		key[i] = (u8)(i);
	r = SDF_ImportKey(hSessionHandle, key, 16, &hKey);
	if(r)
	{
		printf("import session key fail:%x\n", r);
		return r;	
	}

	do
	{
		uiAlgID = ALGID_ARRAY[rand()%0x4];

		printf("---------------%d(id:%x)---------------\n",cnt++, uiAlgID);
		datalen = rand()%0x10000*16;
		//datalen  = 0x20;
		if(datalen==0)
			datalen = 16;
		printf("datalen = %d\n",datalen);

		src_data = malloc(datalen);
		enc_data = malloc(datalen);
		dec_data = malloc(datalen);

		for(i=0;i<16;i++)
		{
			iv[i] = 0x55;
		}
		for(i=0;i<datalen;i++)
		{
			src_data[i] = rand();
			enc_data[i] = 0;
			dec_data[i] = 0;
		}


		for(i=0;i<16;i++)
		{
			uciv[i] = iv[i];
		}
		r = SDF_Encrypt(hSessionHandle,hKey,uiAlgID,uciv,src_data,datalen,enc_data,&enc_datalen);
		if(r)
		{
			printf("Encrypt fail:%x\n", r);
			return r;
		}
		printf("enc_datalen :%x\n", enc_datalen);

		for(i=0;i<16;i++)
		{
			uciv[i] = iv[i];
		}
		r = SDF_Decrypt(hSessionHandle,hKey,uiAlgID,uciv,enc_data,enc_datalen,dec_data,&dec_datalen);
		if(r)
		{
			printf("Decrypt fail:%x\n", r);
			return r;
		}
		printf("dec_datalen :%x\n", dec_datalen);
		if((dec_datalen != datalen)||(memcmp(dec_data, src_data, datalen)))
		{
			printf("source data != dec data \n");

			return -1;
		}
		else
		{
			printf("%s() - success\n",__func__);	

		}
		//while(1);
		free(src_data);
		free(enc_data);
		free(dec_data);
	}while(cnt<0x100);

	r = SDF_DestroyKey(hSessionHandle, hKey);
	if(r)
	{
		printf("destroy session key1 fail:%x\n", r);
		return r;
	} 	
#endif
	printf("%s() - success\n", __func__);
	return 0;		
}
//ecb-enc
u32 Symm_ECB_Enc_Test(void *hSessionHandle,u32 uiAlgID,u8* key,u8* srcdata,u8* dstdata,u32 len)
{
	u32 r;	
	void *hKey;
	unsigned int enclen = 0;
	unsigned char *encdata;
	encdata = malloc(len);

	r = SDF_ImportKey(hSessionHandle, key, 16, &hKey);
	if(r)
	{
		printf("import session key fail:%x\n", r);
		free(encdata);
		return r;	
	}
	
	r = SDF_Encrypt(hSessionHandle, hKey, uiAlgID, NULL, srcdata, len, encdata, &enclen);
	if(r)
	{
		printf("encrypt data fail:%x\n", r);
		free(encdata);
		return r;
	}
#if 0
	printf("enclen %d\n", enclen);
	print_data("encrypt data:", encdata, enclen);
#endif	
	if((enclen != len) || memcmp(encdata, dstdata, len))
	{
		printf("%s()-src data != dst data\n", __func__);
		free(encdata);
		return 1;
	}
	
	r = SDF_DestroyKey(hSessionHandle, hKey);
	if(r)
	{
		printf("destroy session key fail:%x\n", r);
		free(encdata);
		return r;
	} 
	//printf("%s() - success\n", __func__);
	free(encdata);
	return 0;	
	
}
//ecb-dec
u32 Symm_ECB_Dec_Test(void *hSessionHandle,u32 uiAlgID,u8* key,u8* srcdata,u8* dstdata,u32 len)
{
	u32 r;	
	void *hKey;
	unsigned int declen = 0;
	unsigned char *decdata;
	decdata = malloc(len);

	r = SDF_ImportKey(hSessionHandle, key, 16, &hKey);
	if(r)
	{
		printf("import session key fail:%x\n", r);
		free(decdata);
		return r;	
	}
	r = SDF_Decrypt(hSessionHandle, hKey, uiAlgID, NULL, srcdata, len, decdata, &declen);
	if(r)
	{
		printf("decrypt data fail:%x\n", r);
		free(decdata);
		return r;
	}
#if 0
	print_data("decrypt data:", decdata, declen);
#endif
	if((declen != len) || memcmp(decdata, dstdata, len))
	{
		printf("%s()-src data != dst data\n", __func__);
		free(decdata);
		return 1;
	}
	
	r = SDF_DestroyKey(hSessionHandle, hKey);
	if(r)
	{
		printf("destroy session key fail:%x\n", r);
		free(decdata);
		return r;
	} 
	//printf("%s() - success\n", __func__);
	free(decdata);
	return 0;	
	
}
//cbc-enc
u32 Symm_CBC_Enc_Test(void *hSessionHandle,u32 uiAlgID,u8* key,u8* iv,u8* srcdata,u8* dstdata,u32 len)
{
	u32 r;	
	void *hKey;
	unsigned char tempIV[16];
	unsigned int enclen = 0;
	unsigned int enclen0 = 0;
	unsigned int enclen1 = 0;
	unsigned char *encdata;
	encdata = malloc(len);
	

	r = SDF_ImportKey(hSessionHandle, key, 16, &hKey);
	if(r)
	{
		printf("import session key fail:%x\n", r);
		free(encdata);
		return r;	
	}
#if 0
	r = SDF_Encrypt(hSessionHandle, hKey, uiAlgID, iv, srcdata, 16, encdata, &enclen0);
	if(r)
	{
		printf("encrypt data fail:%x\n", r);
		return r;
	}
	r = SDF_Encrypt(hSessionHandle, hKey, uiAlgID, iv, srcdata+16, 16, encdata+16, &enclen1);
	if(r)
	{
		printf("encrypt data fail:%x\n", r);
		return r;
	}
	enclen = enclen0+enclen1;
#else
#if 0
	print_data("src data:", srcdata, 1600);
	print_data("key:", key, 16);
	print_data("iv:", iv, 16);
#endif
	if(iv)
		memcpy(tempIV, iv, 16);
	r = SDF_Encrypt(hSessionHandle, hKey, uiAlgID, tempIV, srcdata, len, encdata, &enclen);
	if(r)
	{
		printf("encrypt data fail:%x\n", r);
		free(encdata);
		return r;
	}
#endif
#if 0
	print_data("decrypt data:", encdata, enclen);
	print_data("iv:", tempIV, 16);
#endif
	if((enclen != len) || memcmp(encdata, dstdata, len))
	{
		printf("%s()-src data != dst data\n", __func__);
		free(encdata);
		return 1;
	}
	
	r = SDF_DestroyKey(hSessionHandle, hKey);
	if(r)
	{
		printf("destroy session key fail:%x\n", r);
		free(encdata);
		return r;
	} 
	//printf("%s() - success\n", __func__);
	free(encdata);
	return 0;	
	
}
//cbc-dec
u32 Symm_CBC_Dec_Test(void *hSessionHandle,u32 uiAlgID,u8* key,u8* iv,u8* srcdata,u8* dstdata,u32 len)
{
	u32 r;	
	void *hKey;
	unsigned char tempIV[16];
	unsigned int declen = 0;
	unsigned int declen0 = 0;
	unsigned int declen1 = 0;
	unsigned char *decdata;
	decdata = malloc(len);

	r = SDF_ImportKey(hSessionHandle, key, 16, &hKey);
	if(r)
	{
		printf("import session key fail:%x\n", r);
		free(decdata);
		return r;	
	}
#if 0
	r = SDF_Decrypt(hSessionHandle, hKey, uiAlgID, iv, srcdata, 16, decdata, &declen0);
	if(r)
	{
		printf("decrypt data fail:%x\n", r);
		return r;
	}
	r = SDF_Decrypt(hSessionHandle, hKey, uiAlgID, iv, srcdata+16, 16, decdata+16, &declen1);
	if(r)
	{
		printf("decrypt data fail:%x\n", r);
		return r;
	}
	declen = declen0+declen1;
#else
	if(iv)
		memcpy(tempIV, iv, 16);
	r = SDF_Decrypt(hSessionHandle, hKey, uiAlgID, tempIV, srcdata, len, decdata, &declen);
	if(r)
	{
		printf("decrypt data fail:%x\n", r);
		free(decdata);
		return r;
	}
#endif
#if 0
	print_data("decrypt data:", decdata, declen);
	print_data("iv:", tempIV, 16);
#endif
	if((declen != len) || memcmp(decdata, dstdata, len))
	{
		printf("%s()-src data != dst data\n", __func__);
		free(decdata);
		return 1;
	}
	
	r = SDF_DestroyKey(hSessionHandle, hKey);
	if(r)
	{
		printf("destroy session key fail:%x\n", r);
		free(decdata);
		return r;
	} 
	//printf("%s() - success\n", __func__);
	free(decdata);
	return 0;	
	
}

u32 Symm_Validity_Test(void *hSessionHandle)
{
	u32 r;	
	void *hKey;
	int i;
	u32 uiAlgID;
	u8 iv[16]={0};
	u8 key[16]={0};
	struct symm_str *pstr;
	u8 * p_srcdata;
	u8 * p_dstdata; 
	u32 datalen;

				
#if SM1_STAND_TEST
	uiAlgID = SGD_SM1_ECB;
	for(i=0;i<5;i++)
	{
		pstr = &sm1_ecb_enc_str[i];
		r = Symm_ECB_Enc_Test(hSessionHandle,uiAlgID,pstr->pkey,pstr->psrcdat,pstr->pdstdat,pstr->len);
		if(r)
		{
			printf("sm1 ecb enc fail[%d]:%x\n", i,r);
			return r;	
		}
	}
	printf("sm1 ecb enc standard test success!\n");

	uiAlgID = SGD_SM1_ECB;
	for(i=0;i<5;i++)
	{
		pstr = &sm1_ecb_dec_str[i];
		r = Symm_ECB_Dec_Test(hSessionHandle,uiAlgID,pstr->pkey,pstr->psrcdat,pstr->pdstdat,pstr->len);
		if(r)
		{
			printf("sm1 ecb dec fail[%d]:%x\n", i,r);
			return r;	
		}
	}
	printf("sm1 ecb dec standard test success!\n");

	uiAlgID = SGD_SM1_CBC;
	for(i=0;i<5;i++)
	{
		pstr = &sm1_cbc_enc_str[i];
		r = Symm_CBC_Enc_Test(hSessionHandle,uiAlgID,pstr->pkey,pstr->piv,pstr->psrcdat,pstr->pdstdat,pstr->len);
		if(r)
		{
			printf("sm1 cbc enc fail[%d]:%x\n", i,r);
			return r;	
		}
	}
	printf("sm1 cbc enc standard test success!\n");

	uiAlgID = SGD_SM1_CBC;
	for(i=0;i<5;i++)
	{
		pstr = &sm1_cbc_dec_str[i];
		r = Symm_CBC_Dec_Test(hSessionHandle,uiAlgID,pstr->pkey,pstr->piv,pstr->psrcdat,pstr->pdstdat,pstr->len);
		if(r)
		{
			printf("sm1 cbc dec fail[%d]:%x\n", i,r);
			return r;	
		}
	}
	printf("sm1 cbc dec standard test success!\n");

#endif
#if SM4_STAND_TEST
	uiAlgID = SGD_SMS4_ECB;
	for(i=0;i<5;i++)
	{
		pstr = &sms4_ecb_enc_str[i];
		r = Symm_ECB_Enc_Test(hSessionHandle,uiAlgID,pstr->pkey,pstr->psrcdat,pstr->pdstdat,pstr->len);
		if(r)
		{
			printf("sms4 ecb enc fail[%d]:%x\n", i,r);
			return r;	
		}
	}
	printf("sms4 ecb enc standard test success!\n");

	uiAlgID = SGD_SMS4_ECB;
	for(i=0;i<5;i++)
	{
		pstr = &sms4_ecb_dec_str[i];
		r = Symm_ECB_Dec_Test(hSessionHandle,uiAlgID,pstr->pkey,pstr->psrcdat,pstr->pdstdat,pstr->len);
		if(r)
		{
			printf("sms4 ecb dec fail[%d]:%x\n", i,r);
			return r;	
		}
	}
	printf("sms4 ecb dec standard test success!\n");

	uiAlgID = SGD_SMS4_CBC;
	for(i=0;i<5;i++)
	{
		pstr = &sms4_cbc_enc_str[i];
		r = Symm_CBC_Enc_Test(hSessionHandle,uiAlgID,pstr->pkey,pstr->piv,pstr->psrcdat,pstr->pdstdat,pstr->len);
		if(r)
		{
			printf("sms4 cbc enc fail[%d]:%x\n", i,r);
			return r;	
		}
	}
	printf("sms4 cbc enc standard test success!\n");

	uiAlgID = SGD_SMS4_CBC;
	for(i=0;i<5;i++)
	{
		pstr = &sms4_cbc_dec_str[i];
		r = Symm_CBC_Dec_Test(hSessionHandle,uiAlgID,pstr->pkey,pstr->piv,pstr->psrcdat,pstr->pdstdat,pstr->len);
		if(r)
		{
			printf("sms4 cbc dec fail[%d]:%x\n", i,r);
			return r;	
		}
	}
	printf("sms4 cbc dec standard test success!\n");
#endif

#if SSF33_STAND_TEST
	uiAlgID = SGD_SSF33_ECB;
	for(i=0;i<5;i++)
	{
		pstr = &ssf33_ecb_enc_str[i];
		r = Symm_ECB_Enc_Test(hSessionHandle,uiAlgID,pstr->pkey,pstr->psrcdat,pstr->pdstdat,pstr->len);
		if(r)
		{
			printf("ssf33 ecb enc fail[%d]:%x\n", i,r);
			return r;	
		}
	}
	printf("ssf33 ecb enc standard test success!\n");

	uiAlgID = SGD_SSF33_ECB;
	for(i=0;i<5;i++)
	{
		pstr = &ssf33_ecb_dec_str[i];
		r = Symm_ECB_Dec_Test(hSessionHandle,uiAlgID,pstr->pkey,pstr->psrcdat,pstr->pdstdat,pstr->len);
		if(r)
		{
			printf("ssf33 ecb dec fail[%d]:%x\n", i,r);
			return r;	
		}
	}
	printf("ssf33 ecb dec standard test success!\n");

	uiAlgID = SGD_SSF33_CBC;
	for(i=0;i<5;i++)
	{
		pstr = &ssf33_cbc_enc_str[i];
		r = Symm_CBC_Enc_Test(hSessionHandle,uiAlgID,pstr->pkey,pstr->piv,pstr->psrcdat,pstr->pdstdat,pstr->len);
		if(r)
		{
			printf("ssf33 cbc enc fail[%d]:%x\n", i,r);
			return r;	
		}
	}
	printf("ssf33 cbc enc standard test success!\n");

	uiAlgID = SGD_SSF33_CBC;
	for(i=0;i<5;i++)
	{
		pstr = &ssf33_cbc_dec_str[i];
		r = Symm_CBC_Dec_Test(hSessionHandle,uiAlgID,pstr->pkey,pstr->piv,pstr->psrcdat,pstr->pdstdat,pstr->len);
		if(r)
		{
			printf("ssf33 cbc dec fail[%d]:%x\n", i,r);
			return r;	
		}
	}
	printf("ssf33 cbc dec standard test success!\n");
#endif
	return 0;		
}

u32 File_Test(void *hSessionHandle)
{
	u32  r;
	unsigned char *write_buf;
	unsigned char *read_buf;
	int len;
	int i;
	unsigned char write_offset[0x10] = {0x76,0x9d,0xd8,0x22,0xae,0x97,0x9b,0x7e,0xba,0x75,0x43,0xc6,0x63,0xe6,0xfd,0x43};
	unsigned char read_offset[0x10] = {0};

	printf("%s()-start\n", __func__);

	r = SDF_CreateFile(hSessionHandle, "test", 4, 0x1000);
	if(r)
	{
		printf("SDF_CreateFile fail:%x\n", r);
		return r;
	}

	len = 0x800;
	write_buf = malloc(len);
	if(write_buf == NULL)
	{
		printf("write buf alloc fail\n");
		goto err;
	}
	for(i=0; i<len; i++)
		write_buf[i] = (unsigned char)(i);
	r = SDF_WriteFile(hSessionHandle, "test", 4, 0, len , write_buf);
	if(r)
	{
		printf("SDF_WriteFile fail:%x\n", r);
		goto err;
	}

	r = SDF_WriteFile(hSessionHandle, "test", 4, 0x900 , 0x10, write_offset);
	if(r)
	{
		printf("SDF_WriteFile offset fail:%x\n", r);
		goto err;
	}

	len = 0x400;
	read_buf = malloc(len);
	if(read_buf == NULL)
	{
		printf("read buf alloc fail\n");
		goto err;
	}
	r = SDF_ReadFile(hSessionHandle, "test", 4, 0,&len, read_buf);
	if(r)
	{
		printf("SDF_ReadFile faile:%x\n", r);
		goto err;
	}
	if(len != 0x400 || memcmp(read_buf, write_buf, len))
	{
		printf("read data != write data \n");
		goto err;
	}else{
		printf("read data == write data \n");
	}

	len = 0x10;
	r = SDF_ReadFile(hSessionHandle, "test", 4, 0x900,&len, read_offset);
	if(r)
	{
		printf("SDF_ReadFile offset faile:%x\n", r);
		goto err;
	}
	if(len != 0x10 || memcmp(read_offset, write_offset, len))
	{
		printf("read offset != write offset \n");
		goto err;
	}else{
		printf("read offset == write offset \n");
	}

err:
	if(write_buf)
		free(write_buf);
	if(read_buf)
		free(read_buf);

	r = SDF_DeleteFile(hSessionHandle, "test", 4);
	if(r)
	{
		printf("SDF_DeleteFile offset faile:%x\n", r);
	}

	printf("%s() - success\n", __func__);
	return r;
}


u32 File_Multi_Test(void *hSessionHandle)
{
	u32  r;
	unsigned char *write_buf;
	unsigned char *write_buf1;
	unsigned char *write_buf2;
	unsigned char *read_buf;
	unsigned char *filelist_buf;
	int len;
	int i;
	
	printf("%s()-start\n", __func__);

	r = SDF_CreateFile(hSessionHandle, "test", 4, 0x1000);
	if(r)
	{
		printf("SDF_CreateFile fail:%x\n", r);
		return r;
	}

	r = SDF_CreateFile(hSessionHandle, "test1", 5, 0x1000);
	if(r)
	{
		printf("SDF_CreateFile fail:%x\n", r);
		return r;
	}

	r = SDF_CreateFile(hSessionHandle, "test2", 5, 0x1000);
	if(r)
	{
		printf("SDF_CreateFile fail:%x\n", r);
		return r;
	}

	len = 0x800;
	write_buf = malloc(len);
	if(write_buf == NULL)
	{
		printf("write buf alloc fail\n");
		goto err;
	}
	write_buf1 = malloc(len);
	if(write_buf1 == NULL)
	{
		printf("write buf 1 alloc fail\n");
		goto err;
	}
	write_buf2 = malloc(len);
	if(write_buf2 == NULL)
	{
		printf("write buf 2 alloc fail\n");
		goto err;
	}
	for(i=0; i<len; i++)
		write_buf[i] = (unsigned char)(i);
	r = SDF_WriteFile(hSessionHandle, "test", 4, 0, len , write_buf);
	if(r)
	{
		printf("SDF_WriteFile fail:%x\n", r);
		goto err;
	}

	for(i=0; i<len; i++)
		write_buf1[i] = (unsigned char)(i+1);
	r = SDF_WriteFile(hSessionHandle, "test1", 5, 0, len , write_buf1);
	if(r)
	{
		printf("SDF_WriteFile 1 fail:%x\n", r);
		goto err;
	}

	for(i=0; i<len; i++)
		write_buf2[i] = (unsigned char)(i+2);
	r = SDF_WriteFile(hSessionHandle, "test2", 5, 0, len , write_buf2);
	if(r)
	{
		printf("SDF_WriteFile 2 fail:%x\n", r);
		goto err;
	}

	len = 0x400;
	read_buf = malloc(len);
	if(read_buf == NULL)
	{
		printf("read buf alloc fail\n");
		goto err;
	}
	r = SDF_ReadFile(hSessionHandle, "test1", 5, 0,&len, read_buf);
	if(r)
	{
		printf("SDF_ReadFile 1 faile:%x\n", r);
		goto err;
	}
	if(len != 0x400 || memcmp(read_buf, write_buf1, len))
	{
		printf("read data 1 != write data 1 \n");
		goto err;
	}else{
		printf("read data 1 == write data 1 \n");
	}

	len = 0x400;
	r = SDF_ReadFile(hSessionHandle, "test", 4, 0,&len, read_buf);
	if(r)
	{
		printf("SDF_ReadFile  faile:%x\n", r);
		goto err;
	}
	if(len != 0x400 || memcmp(read_buf, write_buf, len))
	{
		printf("read data != write data \n");
		goto err;
	}else{
		printf("read data == write data \n");
	}


	len = (SDF_FILE_NAME_MAX_LEN+1)*SDF_FILE_MAX_COUNT;
	filelist_buf = malloc(len);
	if(filelist_buf == NULL)
	{
		printf("filelist_buf buf alloc fail\n");
		goto err;
	} 
	r = EVDF_EnumFiles(hSessionHandle, filelist_buf, &len);
	if(r)
	{
		printf("EVDF_EnumFiles  faile:%x\n", r);
		goto err;
	}
	for(i=0; i<len; i+=(SDF_FILE_NAME_MAX_LEN+1))
	{
		printf("FILE[%d] : %s\n", i/(SDF_FILE_NAME_MAX_LEN+1), &filelist_buf[i]);
	}
	

	r = SDF_DeleteFile(hSessionHandle, "test", 4);
	if(r)
	{
		printf("SDF_DeleteFile  faile:%x\n", r);
		goto err;
	}

	r = SDF_DeleteFile(hSessionHandle, "test1", 5);
	if(r)
	{
		printf("SDF_DeleteFile 1 faile:%x\n", r);
		goto err;
	}


	len = 0x400;
	r = SDF_ReadFile(hSessionHandle, "test2", 5, 0,&len, read_buf);
	if(r)
	{
		printf("SDF_ReadFile 2 faile:%x\n", r);
		goto err;
	}
	if(len != 0x400 || memcmp(read_buf, write_buf2, len))
	{
		printf("read data 2 != write data 2\n");
		goto err;
	}else{
		printf("read data 2 == write data 2\n");
	}


	r = EVDF_EnumFiles(hSessionHandle, filelist_buf, &len);
	if(r)
	{
		printf("EVDF_EnumFiles  faile:%x\n", r);
		goto err;
	}
	for(i=0; i<len; i+=(SDF_FILE_NAME_MAX_LEN+1))
	{
		printf("FILE[%d] : %s\n", i/(SDF_FILE_NAME_MAX_LEN+1), &filelist_buf[i]);
	}

err:
	if(write_buf)
		free(write_buf);
	if(write_buf1)
		free(write_buf1);
	if(write_buf2)
		free(write_buf2);
	if(read_buf)
		free(read_buf);
	if(filelist_buf)
		free(filelist_buf);

	r = SDF_DeleteFile(hSessionHandle, "test2", 5);
	if(r)
	{
		printf("SDF_DeleteFile offset faile:%x\n", r);
	}

	printf("%s() - success\n", __func__);
	return r;
}



u32 Symm_Test(void *hSessionHandle)
{
	int r;
	u32 i = 0;
	u32 j = 0;	
	u32 cnt = 0;
	u8  key[32] = {0};
	u8  temp_iv[16] = {0};
        u8  iv[16] = {0};
	void *hKey;
	u32 ulAlgID;
	u32 ALGID_ARRAY[20] = {SGD_SM1_ECB, SGD_SM1_CBC, SGD_SM1_CFB, SGD_SM1_OFB,
						SGD_SMS4_ECB, SGD_SMS4_CBC,SGD_SMS4_CFB, SGD_SMS4_OFB,
						SGD_SSF33_ECB, SGD_SSF33_CBC,SGD_SSF33_CFB, SGD_SSF33_OFB,
						SGD_SM6_ECB, SGD_SM6_CBC, SGD_SM6_CFB, SGD_SM6_OFB,
						SGD_AES_ECB, SGD_AES_CBC, SGD_AES_CFB, SGD_AES_OFB};

	BYTE *src_data = NULL;
	BYTE *enc_data = NULL;
	BYTE *dec_data = NULL;	

	u32 enc_datalen;
	u32 dec_datalen;
	u32 datalen;

	srand((unsigned int)time(NULL));
	do{
		ulAlgID = ALGID_ARRAY[rand()%20];

		printf("---------------%d(id:%x)---------------\n",cnt++, ulAlgID);
		datalen = rand()%0x10000*16;
		//datalen  = 0x20;
		if(datalen==0)
			datalen = 16;
		printf("datalen = 0x%x\n",datalen);

		src_data = malloc(datalen);
		enc_data = malloc(datalen);
		dec_data = malloc(datalen);

		for(i=0;i<16;i++)
		{
			key[i] = (u8)rand();
			iv[i] = (u8)rand();
		}
		for(i=0;i<datalen;i++)
		{
			src_data[i] = (u8)rand();
			enc_data[i] = 0;
			dec_data[i] = 0;
		}

		r = SDF_ImportKey(hSessionHandle, key, 16, &hKey);
		if(r)
		{
			printf("import session key fail:%x\n", r);
			return r;	
		}

		memcpy(temp_iv, iv, 16);
		r = SDF_Encrypt(hSessionHandle, hKey, ulAlgID, temp_iv, src_data, datalen, enc_data, &enc_datalen);
		if(r)
		{
			printf("encrypt data fail:%x\n", r);
			return r;
		}

		memcpy(temp_iv, iv, 16);
		r = SDF_Decrypt(hSessionHandle, hKey, ulAlgID, temp_iv, enc_data, enc_datalen, dec_data, &dec_datalen);
		if(r)
		{
			printf("decrypt data fail:%x\n", r);
			return r;
		}	

		r = SDF_DestroyKey(hSessionHandle,hKey);
		if(r)
		{
			printf("destroy session key fail:%x\n", r);
			return r;
		}
		
		printf("dec_datalen :0x%x\n", dec_datalen);
		if((dec_datalen != datalen)||(memcmp(dec_data, src_data, datalen)))
		{
			printf("source data != dec data\n");

			return -1;
		}
		else
		{
			printf("%s() - success\n",__func__);	

		}
		
		free(src_data);
		free(enc_data);
		free(dec_data);
	}while(cnt<0x80);
	
	return 0;	
}

u32 Alg_Performance_Test(void *hSessionHandle)
{
	u32 r;
#if SM1_ECB_PER_TEST
	r = sm1_ecb_performance_test(hSessionHandle);
	if(r)
            return r;
#endif
#if SM1_CBC_PER_TEST
	r = sm1_cbc_performance_test(hSessionHandle);
	if(r)
            return r;
#endif
#if SMS4_ECB_PER_TEST
	r = sms4_ecb_performance_test(hSessionHandle);
	if(r)
            return r;
#endif
#if SMS4_CBC_PER_TEST
	r = sms4_cbc_performance_test(hSessionHandle);
	if(r)
            return r;
#endif
#if SSF33_ECB_PER_TEST
	r = ssf33_ecb_performance_test(hSessionHandle);
	if(r)
            return r;
#endif
#if SSF33_CBC_PER_TEST
	r = ssf33_cbc_performance_test(hSessionHandle);
	if(r)
            return r;
#endif
#if SM3_PER_TEST
	r = sm3_performance_test(hSessionHandle);
	if(r)
            return r;
#endif
#if SM2_GENKEY_PER_TEST
	r = sm2_genkey_performance_test(hSessionHandle);
	if(r)
            return r;
#endif
#if SM2_ENC_DEC_PER_TEST
	r = sm2_ext_enc_dec_performance_test(hSessionHandle);
	if(r)
            return r;
	r = sm2_int_enc_dec_performance_test(hSessionHandle);
	if(r)
            return r;	
#endif
#if SM2_SIG_VER_PER_TEST
	r = sm2_sig_ver_performance_test(hSessionHandle);
	if(r)
            return r;
#endif
#if SM2_EXH_KEY_PER_TEST
	r = sm2_int_exchange_key_performance_test(hSessionHandle);
	if (r)
   		return r;
#endif	
#if RSA_GENKEY_PER_TEST
	r = rsa_genkey_performance_test(hSessionHandle);
	if(r)
            return r;
#endif
#if RSA_EXT_OP_PER_TEST
	r = rsa_ext_op_performance_test(hSessionHandle);
	if(r)
            return r;
#endif
#if RSA_INT_OP_PER_TEST
	r = rsa_int_op_performance_test(hSessionHandle);
	if(r)
            return r;
#endif

	return 0;
}


u32 RSA_Validity_Test(void *hSessionHandle)
{
	u32 r;
	RSArefPublicKey rsapubkey;
	RSArefPrivateKey rsaprikey;
	int i,j;
	unsigned char data[256];
	unsigned char encdata[256];
	unsigned char decdata[256];
	unsigned int datalen;
	unsigned int enclen;
	unsigned int declen;
	struct rsa_str * pstr;
	unsigned char temp_rsa_keypair_2048[1152];

	printf("%s()-start\n", __func__);
#if 1
	for(i=0;i<5;i++)
	{
		pstr = &rsa_std_pub_str[i];
		memcpy(temp_rsa_keypair_2048,pstr->pkey,1152);
		rsapubkey.bits = 2048;
		memcpy(rsapubkey.m, temp_rsa_keypair_2048, RSAref_MAX_LEN);
	//	c_reverse(rsapubkey.m, RSAref_MAX_LEN);	
		//c_reverse_u32(rsapubkey.m, RSAref_MAX_LEN);	
		rsaprikey.bits = 2048;
		memcpy(rsaprikey.m, temp_rsa_keypair_2048, RSAref_MAX_LEN);
		//c_reverse(rsaprikey.m, RSAref_MAX_LEN);	
		memcpy(rsaprikey.prime[0], temp_rsa_keypair_2048+512, RSAref_MAX_PLEN);
		//c_reverse(rsaprikey.prime[0], RSAref_MAX_LEN/2);
		memcpy(rsaprikey.prime[1], temp_rsa_keypair_2048+640, RSAref_MAX_PLEN);
		//c_reverse(rsaprikey.prime[1], RSAref_MAX_LEN/2);	
		memcpy(rsaprikey.pexp[0], temp_rsa_keypair_2048+896, RSAref_MAX_PLEN);
		//c_reverse(rsaprikey.pexp[0], RSAref_MAX_LEN/2);
		memcpy(rsaprikey.pexp[1], temp_rsa_keypair_2048+1024, RSAref_MAX_PLEN);
		//c_reverse(rsaprikey.pexp[1], RSAref_MAX_LEN/2);
		memcpy(rsaprikey.coef, temp_rsa_keypair_2048+768, RSAref_MAX_PLEN);
		//c_reverse(rsaprikey.coef, RSAref_MAX_LEN/2);
		memcpy(rsaprikey.d, temp_rsa_keypair_2048+256, RSAref_MAX_LEN);
		//c_reverse(rsaprikey.d, RSAref_MAX_LEN);

		datalen = 256;
		enclen = 256;
		memcpy(data,pstr->psrcdat,256);
	//	c_reverse(data, 256);	

		r = SDF_ExternalPublicKeyOperation_RSA(hSessionHandle, &rsapubkey, data, datalen, encdata, &enclen);
		if(r)
		{
			printf("external rsa public key operation fail:%x\n", r);
			return r;
		}
		//print_data("encrypt data:", encdata, enclen);
		if(memcmp(encdata, pstr->pdstdat, datalen))
		{	
			printf("%s()-enc data != dst data\n", __func__);
			return 1;
		}

		printf("rsa pubkey op success[%d]\n",i);
	}
#endif	
#if 1
	for(i=0;i<5;i++)
	{

		pstr = &rsa_std_pri_str[i];
		memcpy(temp_rsa_keypair_2048,pstr->pkey,1152);
		rsapubkey.bits = 2048;
		memcpy(rsapubkey.m, temp_rsa_keypair_2048, RSAref_MAX_LEN);
		//c_reverse(rsapubkey.m, RSAref_MAX_LEN);	
		rsaprikey.bits = 2048;
		memcpy(rsaprikey.m, temp_rsa_keypair_2048, RSAref_MAX_LEN);
		//c_reverse(rsaprikey.m, RSAref_MAX_LEN);	
		//memcpy(rsaprikey.prime[0], rsa_keypair_2048+RSAref_MAX_PLEN*2, RSAref_MAX_PLEN);
		memcpy(rsaprikey.prime[0], temp_rsa_keypair_2048+512, RSAref_MAX_PLEN);
		//c_reverse(rsaprikey.prime[0], RSAref_MAX_LEN/2);
		//memcpy(rsaprikey.prime[1], rsa_keypair_2048+RSAref_MAX_PLEN*3, RSAref_MAX_PLEN);
		memcpy(rsaprikey.prime[1], temp_rsa_keypair_2048+640, RSAref_MAX_PLEN);
		//c_reverse(rsaprikey.prime[1], RSAref_MAX_LEN/2);	
		//memcpy(rsaprikey.pexp[0], rsa_keypair_2048+RSAref_MAX_PLEN*4, RSAref_MAX_PLEN);
		memcpy(rsaprikey.pexp[0], temp_rsa_keypair_2048+896, RSAref_MAX_PLEN);
		//c_reverse(rsaprikey.pexp[0], RSAref_MAX_LEN/2);
		//memcpy(rsaprikey.pexp[1], rsa_keypair_2048+RSAref_MAX_PLEN*5, RSAref_MAX_PLEN);
		memcpy(rsaprikey.pexp[1], temp_rsa_keypair_2048+1024, RSAref_MAX_PLEN);
		//c_reverse(rsaprikey.pexp[1], RSAref_MAX_LEN/2);
		//memcpy(rsaprikey.coef, rsa_keypair_2048+RSAref_MAX_PLEN*6, RSAref_MAX_PLEN);
		memcpy(rsaprikey.coef, temp_rsa_keypair_2048+768, RSAref_MAX_PLEN);
		//c_reverse(rsaprikey.coef, RSAref_MAX_LEN/2);
		memcpy(rsaprikey.d, temp_rsa_keypair_2048+256, RSAref_MAX_LEN);
		//c_reverse(rsaprikey.d, RSAref_MAX_LEN);

		datalen = 256;
		enclen = 256;
		declen = 256;
		
		r = SDF_ExternalPrivateKeyOperation_RSA(hSessionHandle, &rsaprikey, pstr->psrcdat, enclen, decdata, &declen);
		if(r)
		{
			printf("external rsa private key operation fail:%x\n", r);
			return r;
		}
		//print_data("decrypt data:", decdata, declen);
		if(memcmp(decdata, pstr->pdstdat, datalen))
		{	
			printf("%s()-enc data != dst data\n", __func__);
			return 1;
		}
		printf("rsa prikey op success[%d]\n",i);
	}
#endif
	printf("%s() - success\n", __func__);
	return 0;
}


u32 Create_RandData_File(void *hSessionHandle)
{
	u32  r;
	FILE *fp;
	char *data;

	fp = fopen("rand_file", "w+");
	if(fp == NULL)
	{
		printf("open rand data file fail\n");
		return 1;
	}

	data = malloc(0x10000);
	if(data == NULL)
	{
		printf("alloc data fail\n");
		fclose(fp);
		return 1;
	}

	r = SDF_GenerateRandom(hSessionHandle, 0x10000, data);
	if(r)
	{
		printf("SDF_GenerateRandom fail:%x\n", r);
		free(data);
		fclose(fp);
		return 1;
	}

	fwrite(data, 0x10000, 1, fp);
	free(data);
	fclose(fp);

	return 0;
}




int main()
{
	u32  r;
	void *hDevcieHandle = NULL;
	void *hSessionHandle = NULL;
	unsigned char data[16];
	int i;
	int test_count = 0;
	int loop_count = 0;
	void *pMutex;

#ifdef GET_VERSION
	Get_Version();

	return 0;
#endif

#ifdef INIT_KEY
	Init_Key();
	
	return 0;
#endif


#ifdef MULTI_PER	
	r = multi_performance_test();
	if(r)
	{
		printf("thread_test_symm fail:%x\n", r);
		return r;
	}

	return 0;
#endif

#ifdef THREAD_ALG
	r = thread_test_all_alg();
	if(r)
	{
		printf("thread_test_all_alg fail:%x\n", r);
		return r;
	}

	return 0;
#endif

#ifdef THREAD_SINGLE_DEV
	r = thread_test_single_dev();
	if(r)
	{
		printf("thread_test_sigle_dev fail:%x\n", r);
		return r;
	}	

	return 0;
#endif


	r = SDF_OpenDevice(&hDevcieHandle);
	if(r)
	{
		printf("SDF_OpenDevice fail:%x\n", r);
		return r;
	}

	r = SDF_OpenSession(hDevcieHandle, &hSessionHandle);
	if(r)
	{
		printf("SDF_OpenSession fail:%x\n", r);
		goto err;
	}
	printf("open session ok\n");

do{
	
#ifdef RAND
	memset(data, 0x00, 16);
	r = SDF_GenerateRandom(hSessionHandle, 16, data);
	if(r)
	{
		printf("SDF_GenerateRandom fail:%x\n", r);
		goto err;
	}
	print_data("random data", data, 16);
#endif
#ifdef INFO
	r = GetDeviceInfo_Test(hSessionHandle);
	if(r)
	{
		printf("GetDeviceInfo_Test fail:%x\n", r);
		goto err;	
	}
#endif

#ifdef RANDFILE
	r = Create_RandData_File(hSessionHandle);
	if(r)
	{
		printf("Create_RandData_File fail:%x\n", r);

		goto err;
	}
#endif


#ifdef KEY_ACCESS
	r = GetAccessRight(hSessionHandle);
	if(r)
	{
		printf("GetAccessRight fail:%x\n", r);

		goto err;
	}
#endif

#ifdef SM9
	r = SM9_Test(hSessionHandle);
	if(r)
	{
		printf("ECC_Test fail:%x\n", r);
		goto err;
	}
#endif

#ifdef ECC
	r = ECC_Test(hSessionHandle);
	if(r)
	{
		printf("ECC_Test fail:%x\n", r);
		goto err;
	}
#endif

#ifdef RSA
	r = RSA_Test(hSessionHandle);
	if(r)
	{
		printf("RSA_Test fail:%x\n", r);
		goto err;
	}	
#endif

#ifdef RSA1024
	r = RSA1024_Test1(hSessionHandle);
	if(r)
	{
		printf("RSA_Test1 fail:%x\n", r);
		goto err;
	}

	r = RSA1024_Test2(hSessionHandle);
	if(r)
	{
		printf("RSA_Test2 fail:%x\n", r);
		goto err;
	}

	r = RSA1024_ExternalKey_Test(hSessionHandle);
	if(r)
	{
		printf("RSA1024_ExternalKey_Test fail:%x\n", r);
		goto err;
	}

	r = RSA1024_InternalKey_Test(hSessionHandle);
	if(r)
	{
		printf("RSA1024_InternalKey_Test fail:%x\n", r);
		goto err;
	}

	r = RSA1024_SessionKey_Test1(hSessionHandle);
	if(r)
	{
		printf("RSA1024_SessionKey_Test1 fail:%x\n", r);
		goto err;
	}


	r = RSA1024_SessionKey_Test2(hSessionHandle);
	if(r)
	{
		printf("RSA1024_SessionKey_Test2 fail:%x\n", r);
		goto err;
	}


	r = RSA1024_DigitEnvelope_Test(hSessionHandle);
	if(r)
	{
		printf("RSA1024_DigitEnvelope_Test fail:%x\n", r);
		goto err;
	}
#endif

#ifdef ECC_CALC
	r = ECC_Calc_Test(hSessionHandle);
	if(r)
	{
		printf("ECC_Calc_Test fail:%x\n", r);
		goto err;
	}
#endif

#ifdef RSA_CALC
	r = RSA_Calc_Test(hSessionHandle);
	if(r)
	{
		printf("RSA_Calc_Test fail:%x\n", r);
		goto err;
	}
#endif

#ifdef RSA_EXTKEY
	r = RSA_ExternalKey_Test(hSessionHandle);
	if(r)
	{
		printf("RSA_ExternalKey_Test fail:%x\n", r);
		goto err;		
	}
#endif

#ifdef ECC_EXTKEY
	r = ECC_ExternalKey_Test1(hSessionHandle);
	if(r)
	{
		printf("ECC_ExternalKey_Test1 fail:%x\n", r);
		goto err;				
	}

	r = ECC_ExternalKey_Test2(hSessionHandle);
	if(r)
	{
		printf("ECC_ExternalKey_Test2 fail:%x\n", r);
		goto err;				
	}
#endif

#ifdef ECC_INTKEY
	r = ECC_InternalKey_Test1(hSessionHandle);
	if(r)
	{
		printf("ECC_InternalKey_Test1 fail:%x\n", r);
		goto err;				
	}

	r = ECC_InternalKey_Test2(hSessionHandle);
	if(r)
	{
		printf("ECC_InternalKey_Test2 fail:%x\n", r);
		goto err;				
	}

	r = ECC_InternalKey_Test3(hSessionHandle);
	if(r)
	{
		printf("ECC_InternalKey_Test3 fail:%x\n", r);
		goto err;				
	}

#endif

#ifdef RSA_SESSKEY
	r = RSA_SessionKey_Test1(hSessionHandle);
	if(r)
	{
		printf("RSA_SessionKey1 fail:%x\n", r);
		goto err;
	}

	r = RSA_SessionKey_Test2(hSessionHandle);
	if(r)
	{
		printf("RSA_SessionKey2 fail:%x\n", r);
		goto err;
	}
#endif

#ifdef ECC_SESSKEY
	r = ECC_SessionKey_Test1(hSessionHandle);
	if(r)
	{
		printf("ECC_SessionKey1 fail:%x\n", r);
		goto err;
	}

	r = ECC_SessionKey_Test2(hSessionHandle);
	if(r)
	{
		printf("ECC_SessionKey2 fail:%x\n", r);
		goto err;
	}

	r = ECC_SessionKey_Test3(hSessionHandle);
	if(r)
	{
		printf("ECC_SessionKey3 fail:%x\n", r);
		goto err;
	}	

#endif

#ifdef ECC_DE_EXCHANGE
	r = ECC_DigitEnvelope_Test(hSessionHandle);
	if(r)
	{
		printf("ECC_DigitEnvelope_Test fail:%x\n", r);
		goto err;
	}
#endif

#ifdef RSA_DE_EXCHANGE
	r = RSA_DigitEnvelope_Test(hSessionHandle);
	if(r)
	{
		printf("RSA_DigitEnvelope_Test fail:%x\n", r);
		goto err;
	}
#endif

#ifdef ECC_KEY_EXCHANGE
	r = ECC_ExchangeKey_Test(hSessionHandle);
	if(r)
	{
		printf("ECC_ExchangeKey_Test fail:%x\n", r);
		goto err;
	}	
#endif

#ifdef ECC_IMPORT_ENC_KEY
	r = ECC_ImportEncKey_Test(hSessionHandle);
	if(r)
	{
		printf("ECC_ImportEncKey_Test fail:%x\n", r);
		goto err;
	}
#endif

#ifdef RSA_IMPORT_ENC_KEY
	r = RSA_ImportEncKey_Test(hSessionHandle);
	if(r)
	{
		printf("RSA_ImportEncKey_Test fail:%x\n", r);
		goto err;
	}	
#endif

#ifdef KEK_SESS
	r = KEK_Test(hSessionHandle);
	if(r)
	{
		printf("KEK_Test fail:%x\n", r);
		goto err;		
	}
	
//	r = Sesskey_Random_Test(hSessionHandle);
//	if(r)
//	{
//		printf("Sesskey_Random_Test fail:%x\n", r);
//		goto err;		
//	}
#endif

#ifdef SYMM_VALIDITY_TEST

	r = SM1_CFB_Test(hSessionHandle);
	if(r)
	{
		printf("SM1_CFB_Test fail:%x\n", r);
		goto err;		
	}
	
	r = SM1_OFB_Test(hSessionHandle);
	if(r)
	{
		printf("SM1_OFB_Test fail:%x\n", r);
		goto err;		
	}
	
	r = SM6_ECB_Test(hSessionHandle);
	if(r)
	{
		printf("SM6_ECB_Test fail:%x\n", r);
		goto err;		
	}
	
	r = SM6_CBC_Test(hSessionHandle);
	if(r)
	{
		printf("SM6_CBC_Test fail:%x\n", r);
		goto err;		
	}
	
	r = AES_ECB_Test(hSessionHandle);
	if(r)
	{
		printf("AES_ECB_Test fail:%x\n", r);
		goto err;		
	}
	
	r = AES_CBC_Test(hSessionHandle);
	if(r)
	{
		printf("AES_CBC_Test fail:%x\n", r);
		goto err;		
	}	

	r = Symm_Validity_Test(hSessionHandle);
	if(r)
	{
		printf("Symm_Validity_Test fail:%x\n", r);
		goto err;		
	}
#endif

#ifdef SYMM
	r = Symm_Test(hSessionHandle);
	if(r)
	{
		printf("Symm_Test fail:%x\n", r);
		goto err;		
	}
#endif

#ifdef ASYMM_VALIDITY_TEST
	r = Asymm_Validity_Test(hSessionHandle);
	if(r)
	{
		printf("Asymm_Validity_Test fail:%x\n", r);
		goto err;		
	}
#endif

#ifdef RSA_VALIDITY_TEST
	r = RSA_Validity_Test(hSessionHandle);
	if(r)
	{
		printf("RSA_Validity_Test fail:%x\n", r);
		goto err;		
	}
#endif

#ifdef MAC
	r = MAC_Test(hSessionHandle);
	if(r)
	{
		printf("MAC_Test fail:%x\n", r);
		goto err;		
	}	
#endif

#ifdef MAC_STANDARD_TEST
	r = MAC_Standard_Test(hSessionHandle);
	if(r)
	{
		printf("MAC_Standard_Test fail:%x\n", r);
		goto err;		
	}	
#endif

#ifdef HASH
	r = HASH_Test(hSessionHandle);
	if(r)
	{
		printf("HASH_Test fail:%x\n", r);
		goto err;		
	}
#endif
#ifdef HASH_SCATTER_TEST
	r = HASH_Scatter_Test(hSessionHandle);
	if(r)
	{
		printf("HASH_Test fail:%x\n", r);
		goto err;		
	}
#endif

#ifdef HASH_KEY
	r = HASH_Key_Test(hSessionHandle);
	if(r)
	{
		printf("HASH_Key_Test fail:%x\n", r);
		goto err;		
	}

	r = HASH_Key_Test2(hSessionHandle);
	if(r)
	{
		printf("HASH_Key_Test2 fail:%x\n", r);
		goto err;		
	}

	r = HASH_Key_Test3(hSessionHandle);
	if(r)
	{
		printf("HASH_Key_Test3 fail:%x\n", r);
		goto err;		
	}	
#endif

#ifdef HASH_Z
	r = Hash_Z_Test3(hSessionHandle);
	if(r)
	{
		printf("Hash_Z_Test fail:%x\n", r);
		goto err;		
	}
#endif

#ifdef HASH_VALIDITY_TEST

	r = SHA1_Test(hSessionHandle);
	if(r)
	{
		printf("SHA1_Test fail:%x\n", r);
		goto err;		
	}
	
	r = SHA256_Test(hSessionHandle);
	if(r)
	{
		printf("SHA256_Test fail:%x\n", r);
		goto err;		
	}
	
	r = SHA512_Test(hSessionHandle);
	if(r)
	{
		printf("SHA512_Test fail:%x\n", r);
		goto err;		
	}	

	r = SHA0_Test(hSessionHandle);
	if(r)
	{
		printf("SHA0_Test fail:%x\n", r);
		goto err;		
	}	

	r = SHA224_Test(hSessionHandle);
	if(r)
	{
		printf("SHA224_Test fail:%x\n", r);
		goto err;		
	}	

	r = SHA384_Test(hSessionHandle);
	if(r)
	{
		printf("SHA384_Test fail:%x\n", r);
		goto err;		
	}		

	r = HASH_Validity_Test(hSessionHandle);
	if(r)
	{
		printf("HASH_Validity_Test fail:%x\n", r);
		goto err;		
	}

	r = HMAC_Validity_Test(hSessionHandle);
	if(r)
	{
		printf("HMAC_Validity_Test fail:%x\n", r);
		goto err;		
	}	
#endif

#ifdef DEVFILE
	r = File_Test(hSessionHandle);
	if(r)
	{
		printf("File_Test fail:%x\n", r);
		goto err;
	}

	r = File_Multi_Test(hSessionHandle);
	if(r)
	{
		printf("File_Multi_Test fail:%x\n", r);
		goto err;
	}	
#endif

#ifdef IMPORT_KEY
	r = ImportKey_Test(hSessionHandle);
	if(r)
	{
		printf("ImportKey_Test fail:%x\n", r);
		goto err;	
	}

	r = ImportKey_SessionKey_Test(hSessionHandle);
	if(r)
	{
		printf("ImportKey_SessionKey_Test fail:%x\n", r);
		goto err;	
	}
#endif



#ifdef KEY_ACCESS_RIGHT
	r = KeyAccessRight_Test(hSessionHandle);
	if(r)
	{
		printf("KeyAccessRight_Test fail:%x\n", r);
		goto err;		
	}

	r = KeyAccessRight_Manage_Test(hSessionHandle);
	if(r)
	{
		printf("KeyAccessRight_Manage_Test fail:%x\n", r);
		goto err;		
	}
#endif

}while((++loop_count) < 0x1);
err:
	if(hSessionHandle)
		SDF_CloseSession(hSessionHandle);
	if(hDevcieHandle)
		SDF_CloseDevice(hDevcieHandle);

	getchar();

	return r;
}




