#include <sdf.h>
#include <sdf_type.h>
//#include <SKF.h>
//#include <skf_type.h>
#include <stdio.h>
#include <string.h>
#include <malloc.h>
#include <time.h>
#include <sys/time.h>
#include "pert.h"

extern unsigned char rsa_keypair_2048[];

struct timeval start_time, finish_time;

#if 0
int gettimeofday(struct timeval *tp, void *tzp)
{
	return;
}
#endif

u32 sm1_ecb_performance_test(void *hSessionHandle)
{
	u32 r,i;	
	void *hKey;
	unsigned int enclen = 0;
	unsigned int declen = 0;
	//unsigned char srcdata[SM1_L] = {0};
	//unsigned char encdata[SM1_L] = {0};
	//unsigned char dstdata[SM1_L] = {0};
	unsigned char * srcdata = malloc(SM1_L);
	//printf("malloc ok...0\n");
	unsigned char * encdata = malloc(SM1_L);
	//printf("malloc ok...1\n");
	unsigned char * dstdata = malloc(SM1_L);
	//printf("malloc ok...2\n");
	u8 key[16]={0};
	u32 uiAlgID = SGD_SM1_ECB;

	double enc_total_val = 0;
	double dec_total_val = 0;
	
 	for(i=0;i<16;i++)
	{
		key[i] = rand();
	}
 	for(i=0;i<SM1_L;i++)
	{
		srcdata[i] = rand();
	}
	
	printf("-------------------------------------------------\n");
	printf("SM1_L = %d\n", SM1_L);
	printf("SM1_N = %d\n", SM1_N);
	r = SDF_ImportKey(hSessionHandle, key, 16, &hKey);
	if(r)
	{
		printf("import session key fail:%x\n", r);
		return r;	
	}
gettimeofday(&start_time, NULL);
	for(i=0;i<SM1_N;i++)
	{
		r = SDF_Encrypt(hSessionHandle, hKey, uiAlgID, NULL, srcdata, SM1_L, encdata, &enclen);
		if(r)
		{
			printf("encrypt data fail:%x\n", r);
			return r;
		}
	}
gettimeofday(&finish_time, NULL);	
enc_total_val = (finish_time.tv_sec-start_time.tv_sec)*1000000+finish_time.tv_usec - start_time.tv_usec;
fprintf(stdout, "SM1 ecb enc total time : %f us\n", enc_total_val);
fprintf(stdout, "SM1 ecb enc performance: %f Mbps\n", ((double)((8*SM1_L*SM1_N)/((enc_total_val/1000000)*1024*1024))));

gettimeofday(&start_time, NULL);
	for(i=0;i<SM1_N;i++)
	{
		r = SDF_Decrypt(hSessionHandle, hKey, uiAlgID, NULL, encdata, SM1_L, dstdata, &declen);
		if(r)
		{
			printf("decrypt data fail:%x\n", r);
			return r;
		}
	}
gettimeofday(&finish_time, NULL);	
dec_total_val = (finish_time.tv_sec-start_time.tv_sec)*1000000+finish_time.tv_usec - start_time.tv_usec;
fprintf(stdout, "SM1 ecb dec total time : %f us\n", dec_total_val);
fprintf(stdout, "SM1 ecb dec performance: %f Mbps\n", ((double)((8*SM1_L*SM1_N)/((dec_total_val/1000000)*1024*1024))));
#if 1
	//print_data("encrypt data:", encdata, enclen);

	if((enclen != declen) || memcmp(srcdata, dstdata,SM1_L))
	{
		printf("sm1_ecb_performance_test()-src data != dst data\n");
		return 1;
	}
#endif
	free(srcdata);
	free(encdata);
	free(dstdata);
	r = SDF_DestroyKey(hSessionHandle, hKey);
	if(r)
	{
		printf("destroy session key fail:%x\n", r);
		return r;
	} 
	//printf("%s() - success\n", __func__);
	return 0;	
}
u32 sm1_cbc_performance_test(void *hSessionHandle)
{
	u32 r,i;	
	void *hKey;
	unsigned int enclen = 0;
	unsigned int declen = 0;
	//unsigned char srcdata[SM1_L] = {0};
	//unsigned char encdata[SM1_L] = {0};
	//unsigned char dstdata[SM1_L] = {0};
	unsigned char * srcdata = malloc(SM1_L);
	//printf("malloc ok...0\n");
	unsigned char * encdata = malloc(SM1_L);
	//printf("malloc ok...1\n");
	unsigned char * dstdata = malloc(SM1_L);
	//printf("malloc ok...2\n");
	u8 key[16]={0};
	u8 iv[16]={0};
	u32 uiAlgID = SGD_SM1_CBC;

	double enc_total_val = 0;
	double dec_total_val = 0;
	
 	for(i=0;i<16;i++)
	{
		key[i] = rand();
	}
	for(i=0;i<16;i++)
	{
		iv[i] = i;
	}
 	for(i=0;i<SM1_L;i++)
	{
		srcdata[i] = rand();
	}
	
	printf("-------------------------------------------------\n");
	printf("SM1_L = %d\n", SM1_L);
	printf("SM1_N = %d\n", SM1_N);
	r = SDF_ImportKey(hSessionHandle, key, 16, &hKey);
	if(r)
	{
		printf("import session key fail:%x\n", r);
		return r;	
	}
gettimeofday(&start_time, NULL);
	for(i=0;i<SM1_N;i++)
	{
		r = SDF_Encrypt(hSessionHandle, hKey, uiAlgID, iv, srcdata, SM1_L, encdata, &enclen);
		if(r)
		{
			printf("encrypt data fail:%x\n", r);
			return r;
		}
	}
gettimeofday(&finish_time, NULL);	
enc_total_val = (finish_time.tv_sec-start_time.tv_sec)*1000000+finish_time.tv_usec - start_time.tv_usec;
fprintf(stdout, "SM1 cbc enc total time : %f us\n", enc_total_val);
fprintf(stdout, "SM1 cbc enc performance: %f Mbps\n", ((double)((8*SM1_L*SM1_N)/((enc_total_val/1000000)*1024*1024))));

	for(i=0;i<16;i++)
	{
		iv[i] = i;
	}
gettimeofday(&start_time, NULL);
	for(i=0;i<SM1_N;i++)
	{
		r = SDF_Decrypt(hSessionHandle, hKey, uiAlgID, iv, encdata, SM1_L, dstdata, &declen);
		if(r)
		{
			printf("decrypt data fail:%x\n", r);
			return r;
		}
	}
gettimeofday(&finish_time, NULL);	
dec_total_val = (finish_time.tv_sec-start_time.tv_sec)*1000000+finish_time.tv_usec - start_time.tv_usec;
fprintf(stdout, "SM1 cbc dec total time : %f us\n", dec_total_val);
fprintf(stdout, "SM1 cbc dec performance: %f Mbps\n", ((double)((8*SM1_L*SM1_N)/((dec_total_val/1000000)*1024*1024))));
#if 1
	//print_data("encrypt data:", encdata, enclen);

	if((enclen != declen) || memcmp(srcdata, dstdata,SM1_L))
	{
		printf("%s()-src data != dst data\n", __func__);
		return 1;
	}
#endif
	free(srcdata);
	free(encdata);
	free(dstdata);
	r = SDF_DestroyKey(hSessionHandle, hKey);
	if(r)
	{
		printf("destroy session key fail:%x\n", r);
		return r;
	} 
	//printf("%s() - success\n", __func__);
	return 0;	
}


u32 sm2_int_exchange_key_performance_test(void *hSessionHandle)
{
	u32 r;
	int i;
	ECCrefPublicKey PubA, PubB;
	ECCrefPublicKey PubTempA, PubTempB;
	void *hExchA = NULL;
	void *hKeyA = NULL;
	void *hKeyB = NULL;
	double total_val = 0;
	double total_val_a = 0;
	double total_val_b = 0;

	total_val = 0;
	total_val_a = 0;
	total_val_b = 0;
	for(i=0; i<SM2_EXHKEY_N; i++)
	{
		memset(&PubA, 0, sizeof(ECCrefPublicKey));
		memset(&PubB, 0, sizeof(ECCrefPublicKey));
		memset(&PubTempA, 0, sizeof(ECCrefPublicKey));
		memset(&PubTempB, 0, sizeof(ECCrefPublicKey));	
		
		gettimeofday(&start_time, NULL);	
			//A 
		r = SDF_GenerateAgreementDataWithECC(hSessionHandle, 1, 128, (u8*)"1234567812345678", 16, &PubA, &PubTempA, &hExchA);
		if(r)
		{
			printf("SDF_GenerateAgreementDataWithECC fail:%x\n", r);
			goto err;	
		}

		gettimeofday(&finish_time, NULL);
		total_val_a += (finish_time.tv_sec-start_time.tv_sec)*1000000+finish_time.tv_usec - start_time.tv_usec;

		gettimeofday(&start_time, NULL);	
		//B
		r = SDF_GenerateAgreementDataAndKeyWithECC(hSessionHandle, 2, 128, (u8*)"1234567812345678", 16, (u8*)"1234567812345678", 16,
					&PubA, &PubTempA, &PubB, &PubTempB, &hKeyB);
		if(r)
		{
			printf("SDF_GenerateAgreementDataAndKeyWithECC fail:%x\n", r);
			goto err;		
		}
		gettimeofday(&finish_time, NULL);
		total_val_b += (finish_time.tv_sec-start_time.tv_sec)*1000000+finish_time.tv_usec - start_time.tv_usec;

		gettimeofday(&start_time, NULL);	
		//A
		r = SDF_GenerateKeyWithECC(hSessionHandle, (u8*)"1234567812345678", 16, &PubB, &PubTempB, hExchA, &hKeyA);
		if(r)
		{
			printf("SDF_GenerateKeyWithECC fail:%x\n", r);
			goto err;		
		}

		gettimeofday(&finish_time, NULL);
		total_val_a += (finish_time.tv_sec-start_time.tv_sec)*1000000+finish_time.tv_usec - start_time.tv_usec;

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

	}

	total_val = (total_val_a + total_val_b);

	printf("---------------------------------------------\n");
	fprintf(stdout, "SM2 exchage key time : %f us\n", total_val);
//	fprintf(stdout, "SM2 exchange key performance S=: %f Mbps\n", ((double)((8*SM2_SV_L*SM2_SV_N)/((sign_total_val/1000000)*1024*1024))));
	fprintf(stdout, "SM2 exchange key a+b performance S=: %f time/s\n", ((double)(SM2_EXHKEY_N/(total_val/1000000))));
	fprintf(stdout, "SM2 exchange key a performance S=: %f time/s\n", ((double)(SM2_EXHKEY_N/(total_val_a/1000000))));
	fprintf(stdout, "SM2 exchange key b performance S=: %f time/s\n", ((double)(SM2_EXHKEY_N/(total_val_b/1000000))));
	printf("---------------------------------------------\n");

err:
	return r;	
}


u32 sm2_int_sig_ver_performance_test(void *hSessionHandle)
{

	u32 r,i;	
	int srclen = SM2_SV_L;
	ECCrefPublicKey eccpubkey;
	ECCrefPrivateKey eccprikey;
	ECCSignature sig;	
	unsigned char data[32] = {
		0x0E,0x73,0x73,0x6C,0x74,0x65,0x73,0x74,0x73,0x65,0x72,0x76,0x65,0x72,0x32,0x30,
		0x59,0x30,0x13,0x06,0x07,0x2A,0x86,0x48,0xCE,0x3D,0x02,0x01,0x06,0x08,0x2A,0x81
	};
	double sign_total_val = 0;
	double verify_total_val = 0;
	double extern_verify_total_val = 0;
	
	printf("-------------------------------------------------\n");
	printf("SM2_SV_L = %d\n", SM2_SV_L);
	printf("SM2_SV_N = %d\n", SM2_SV_N);
	gettimeofday(&start_time, NULL);	
	for(i=0;i<SM2_SV_N;i++)
	{
		r = SDF_InternalSign_ECC(hSessionHandle, 1, data, srclen, &sig);
		if(r)
		{
			printf("internal ecc sign data fail:%x\n", r);
			return r;
		}
	}
	gettimeofday(&finish_time, NULL);
	sign_total_val = (finish_time.tv_sec-start_time.tv_sec)*1000000+finish_time.tv_usec - start_time.tv_usec;
	printf("---------------------------------------------\n");
	fprintf(stdout, "SM2 internal sign time : %f us\n", sign_total_val);
	fprintf(stdout, "SM2 internal sign performance S=: %f Mbps\n", ((double)((8*SM2_SV_L*SM2_SV_N)/((sign_total_val/1000000)*1024*1024))));
	fprintf(stdout, "SM2 internal sign performance S=: %f time/s\n", ((double)(SM2_SV_N/(sign_total_val/1000000))));
	printf("---------------------------------------------\n");

	gettimeofday(&start_time, NULL);
	for(i=0;i<SM2_SV_N;i++)
	{
		r = SDF_InternalVerify_ECC(hSessionHandle, 1, data, srclen, &sig);
		if(r)
		{
			printf("internal ecc verify fail:%x\n", r);
			return r;
		}
	}
	
	gettimeofday(&finish_time, NULL);
	verify_total_val = (finish_time.tv_sec-start_time.tv_sec)*1000000+finish_time.tv_usec - start_time.tv_usec;
	printf("---------------------------------------------\n");
	fprintf(stdout, "SM2 internal verify time : %f us\n", verify_total_val);
	fprintf(stdout, "SM2 internal verify performance S=: %f Mbps\n", ((double)((8*SM2_SV_L*SM2_SV_N)/((verify_total_val/1000000)*1024*1024))));
	fprintf(stdout, "SM2 internal verify performance S=: %f time/s\n", ((double)(SM2_SV_N/(verify_total_val/1000000))));
	printf("---------------------------------------------\n");


	r = SDF_ExportSignPublicKey_ECC(hSessionHandle, 1, &eccpubkey);
	if(r)
	{
		printf("export ecc enc public key fail:%x\n", r);
		return r;
	}
	gettimeofday(&start_time, NULL);
	for(i=0;i<SM2_SV_N;i++)
	{
		r = SDF_ExternalVerify_ECC(hSessionHandle, SGD_SM2_1, &eccpubkey, data, srclen, &sig);
		if(r)
		{
			printf("external ecc verify fail:%x\n", r);
			return r;
		}
	}	
	gettimeofday(&finish_time, NULL);
	extern_verify_total_val = (finish_time.tv_sec-start_time.tv_sec)*1000000+finish_time.tv_usec - start_time.tv_usec;
	printf("---------------------------------------------\n");
	fprintf(stdout, "SM2 enternal verify time : %f us\n", extern_verify_total_val);
	fprintf(stdout, "SM2 enternal verify performance S=: %f Mbps\n", ((double)((8*SM2_SV_L*SM2_SV_N)/((extern_verify_total_val/1000000)*1024*1024))));
	fprintf(stdout, "SM2 enternal verify performance S=: %f time/s\n", ((double)(SM2_SV_N/(extern_verify_total_val/1000000))));
	printf("---------------------------------------------\n");

	return 0;
}
u32 sm2_ext_sig_ver_performance_test(void *hSessionHandle)
{
	u32 r,i;
	int srclen = SM2_SV_L;
	ECCrefPublicKey eccpubkey;
	ECCrefPrivateKey eccprikey;
	ECCSignature sig;
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
	double sign_total_val = 0;
	double verify_total_val = 0;
	//double extern_verify_total_val = 0;

	printf("%s()-start\n", __func__);
	
	printf("-------------------------------------------------\n");
	printf("SM2_SV_L = %d\n", SM2_SV_L);
	printf("SM2_SV_N = %d\n", SM2_SV_N);

	for(i=0; i<32; i++)
		data[i] = (u8)(i+0x80);

	memset(&eccprikey, 0, sizeof(ECCrefPrivateKey));
	memcpy(eccprikey.K+32, keypair+64, 32);
	eccprikey.bits = 256;
	gettimeofday(&start_time, NULL);	
	for(i=0;i<SM2_SV_N;i++)
	{
		r = SDF_ExternalSign_ECC(hSessionHandle, SGD_SM2_1, &eccprikey, data, srclen, &sig);
		if(r)
		{
			printf("external ecc sign fail:%x\n", r);
			return r;
		}	
	}
	gettimeofday(&finish_time, NULL);
	sign_total_val = (finish_time.tv_sec-start_time.tv_sec)*1000000+finish_time.tv_usec - start_time.tv_usec;
	printf("---------------------------------------------\n");
	fprintf(stdout, "SM2 external sign time : %f us\n", sign_total_val);
	fprintf(stdout, "SM2 external sign performance S=: %f Mbps\n", ((double)((8*SM2_SV_L*SM2_SV_N)/((sign_total_val/1000000)*1024*1024))));
	fprintf(stdout, "SM2 external sign performance S=: %f time/s\n", ((double)(SM2_SV_N/(sign_total_val/1000000))));
	printf("---------------------------------------------\n");

	memset(&eccpubkey, 0, sizeof(ECCrefPublicKey));
	memcpy(eccpubkey.x+32, keypair, 32);
	memcpy(eccpubkey.y+32, keypair+32, 32);
	eccpubkey.bits = 256;
	gettimeofday(&start_time, NULL);
	for(i=0;i<SM2_SV_N;i++)
	{
		r = SDF_ExternalVerify_ECC(hSessionHandle, SGD_SM2_1, &eccpubkey, data, srclen, &sig);
		if(r)
		{
			printf("external ecc verify fail:%x\n", r);
			return r;
		}
	}
	gettimeofday(&finish_time, NULL);
	verify_total_val = (finish_time.tv_sec-start_time.tv_sec)*1000000+finish_time.tv_usec - start_time.tv_usec;
	printf("---------------------------------------------\n");
	fprintf(stdout, "SM2 external verify time : %f us\n", verify_total_val);
	fprintf(stdout, "SM2 external verify performance S=: %f Mbps\n", ((double)((8*SM2_SV_L*SM2_SV_N)/((verify_total_val/1000000)*1024*1024))));
	fprintf(stdout, "SM2 external verify performance S=: %f time/s\n", ((double)(SM2_SV_N/(verify_total_val/1000000))));
	printf("---------------------------------------------\n");
	
	
	printf("%s() - success\n", __func__);
	return 0;	
}
u32 sm2_sig_ver_performance_test(void *hSessionHandle)
{
        u32 r;
#if SM2_INT_SIG_VER_TEST
	r = sm2_int_sig_ver_performance_test(hSessionHandle);
	if (r)
   		return r;
#endif
#if SM2_EXT_SIG_VER_TEST
	r = sm2_ext_sig_ver_performance_test(hSessionHandle);
	if (r)
   		return r;
#endif
	return 0;

}

u32 sm2_ext_enc_dec_performance_test(void *hSessionHandle)
{
	u32 r,i;
	int srclen = SM2_ED_L;
	unsigned char data[SM2_ED_L];
	unsigned char encdata[256];
	unsigned char decdata[256];
	int declen;
	ECCrefPublicKey eccpubkey;
	ECCrefPrivateKey eccprikey;
	ECCCipher *pecccipher = (ECCCipher *)encdata;	
	double enc_total_val = 0;
	double dec_total_val = 0;
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
	printf("-------------------------------------------------\n");
	printf("SM2_ED_L = %d\n", SM2_ED_L);
	printf("SM2_ED_N = %d\n", SM2_ED_N);

	memset(&eccpubkey, 0, sizeof(ECCrefPublicKey));
	memcpy(eccpubkey.x+32, keypair, 32);
	memcpy(eccpubkey.y+32, keypair+32, 32);
	eccpubkey.bits = 256;
	memset(data, rand(), srclen);

	gettimeofday(&start_time, NULL);
	for(i=0;i<SM2_ED_N;i++)
	{
		r = SDF_ExternalEncrypt_ECC(hSessionHandle, SGD_SM2_3, &eccpubkey, data, srclen, pecccipher);
		if(r)
		{
			printf("external ecc encrypt fail:%x\n", r);
			return r;
		}
	}
	gettimeofday(&finish_time, NULL);
	enc_total_val = (finish_time.tv_sec-start_time.tv_sec)*1000000+finish_time.tv_usec - start_time.tv_usec;
	printf("---------------------------------------------\n");
	fprintf(stdout, "SM2 external encrypt time : %f us\n", enc_total_val);
	fprintf(stdout, "SM2 external encrypt performance S=: %f Mbps\n", ((double)((8*SM2_ED_L*SM2_ED_N)/((enc_total_val/1000000)*1024*1024))));
	fprintf(stdout, "SM2 external encrypt performance: %f time/s\n", ((double)(SM2_ED_N/(enc_total_val/1000000))));
	printf("---------------------------------------------\n");

	memset(&eccprikey, 0, sizeof(ECCrefPrivateKey));
	memcpy(eccprikey.K+32, keypair+64, 32);
	eccprikey.bits = 256;
	
	gettimeofday(&start_time, NULL);
	for(i=0;i<SM2_ED_N;i++)
	{
		declen = 256;
		r = SDF_ExternalDecrypt_ECC(hSessionHandle, SGD_SM2_3, &eccprikey, pecccipher, decdata, &declen);
		if(r)
		{
			printf("external ecc decrypt fail:%x\n", r);
			return r;			
		}
	}
	gettimeofday(&finish_time, NULL);
	dec_total_val = (finish_time.tv_sec-start_time.tv_sec)*1000000+finish_time.tv_usec - start_time.tv_usec;
	printf("---------------------------------------------\n");
	fprintf(stdout, "SM2 external decrypt time : %f us\n", dec_total_val);
	fprintf(stdout, "SM2 external decrypt performance S=: %f Mbps\n", ((double)((8*SM2_ED_L*SM2_ED_N)/((dec_total_val/1000000)*1024*1024))));
	fprintf(stdout, "SM2 external decrypt performance: %f time/s\n", ((double)(SM2_ED_N/(dec_total_val/1000000))));
	printf("---------------------------------------------\n");

	if((declen != srclen) || memcmp(data, decdata, declen))
	{
		printf("%s()-source data != dec data\n", __func__);
		return 1;
	}	
	
	return 0;
}


u32 sm2_int_enc_dec_performance_test(void *hSessionHandle)
{
	u32 r,i;
	int srclen = SM2_ED_L;
	unsigned char data[SM2_ED_L];
	unsigned char encdata[256];
	unsigned char decdata[256];
	int declen;
	ECCrefPublicKey eccpubkey;
	ECCrefPrivateKey eccprikey;
	ECCCipher *pecccipher = (ECCCipher *)encdata;	
	double enc_total_val = 0;
	double dec_total_val = 0;
	unsigned char srcdata[] = {0x55,0x45,0x33,0x23,0x49,0xCD,0x1F,0x10,0x66,0x86,0x73,0x2A,0xE4,0xE8,0x6B,0x7E,
		0x7E,0xA0,0x89,0xEC,0x21,0x9D,0x59,0x4F,0x49,0xCE,0xEA,0x2A,0x6A,0x93,0x00,0xEC};
	printf("-------------------------------------------------\n");
	printf("SM2_ED_L = %d\n", SM2_ED_L);
	printf("SM2_ED_N = %d\n", SM2_ED_N);

	pecccipher = (ECCCipher *)encdata;	
	memset(pecccipher, 0, sizeof(ECCCipher));

	gettimeofday(&start_time, NULL);
	for(i=0;i<SM2_ED_N;i++)
	{
		r = SDF_InternalEncrypt_ECC(hSessionHandle, 1, srcdata, 32, pecccipher);
		if(r)
		{
			printf("internal ecc encrypt fail:%x\n", r);
			return r;			
		}
	}
	gettimeofday(&finish_time, NULL);
	enc_total_val = (finish_time.tv_sec-start_time.tv_sec)*1000000+finish_time.tv_usec - start_time.tv_usec;
	printf("---------------------------------------------\n");
	fprintf(stdout, "SM2 internal encrypt time : %f us\n", enc_total_val);
	fprintf(stdout, "SM2 internal encrypt performance S=: %f Mbps\n", ((double)((8*SM2_ED_L*SM2_ED_N)/((enc_total_val/1000000)*1024*1024))));
	fprintf(stdout, "SM2 internal encrypt performance: %f time/s\n", ((double)(SM2_ED_N/(enc_total_val/1000000))));
	printf("---------------------------------------------\n");

	memset(decdata, 0x00, 256);
	
	gettimeofday(&start_time, NULL);
	for(i=0;i<SM2_ED_N;i++)
	{
		declen = 256;
		r = SDF_InternalDecrypt_ECC(hSessionHandle, 1, pecccipher, decdata, &declen);
		if(r)
		{
			printf("internal ecc decrypt fail:%x\n", r);
			return r;			
		}
	}
	gettimeofday(&finish_time, NULL);
	dec_total_val = (finish_time.tv_sec-start_time.tv_sec)*1000000+finish_time.tv_usec - start_time.tv_usec;
	printf("---------------------------------------------\n");
	fprintf(stdout, "SM2 internal decrypt time : %f us\n", dec_total_val);
	fprintf(stdout, "SM2 internal decrypt performance S=: %f Mbps\n", ((double)((8*SM2_ED_L*SM2_ED_N)/((dec_total_val/1000000)*1024*1024))));
	fprintf(stdout, "SM2 internal decrypt performance: %f time/s\n", ((double)(SM2_ED_N/(dec_total_val/1000000))));
	printf("---------------------------------------------\n");

	if((declen != srclen) || memcmp(data, decdata, declen))
	{
		printf("%s()-source data != dec data\n", __func__);
		return 1;
	}	
	
	return 0;
}


u32 sms4_ecb_performance_test(void *hSessionHandle)
{
	u32 r,i;	
	void *hKey;
	unsigned int enclen = 0;
	unsigned int declen = 0;

	unsigned char * srcdata = malloc(SMS4_L);
	//printf("malloc ok...0\n");
	unsigned char * encdata = malloc(SMS4_L);
	//printf("malloc ok...1\n");
	unsigned char * dstdata = malloc(SMS4_L);
	//printf("malloc ok...2\n");
	u8 key[16]={0};
	u32 uiAlgID = SGD_SMS4_ECB;

	double enc_total_val = 0;
	double dec_total_val = 0;
	
 	for(i=0;i<16;i++)
	{
		key[i] = rand();
	}
 	for(i=0;i<SMS4_L;i++)
	{
		srcdata[i] = rand();
	}
#if 1
	printf("-------------------------------------------------\n");
	printf("SMS4_L = %d\n", SMS4_L);
	printf("SMS4_N = %d\n", SMS4_N);
#endif
	r = SDF_ImportKey(hSessionHandle, key, 16, &hKey);
	if(r)
	{
		printf("import session key fail:%x\n", r);
		return r;	
	}
gettimeofday(&start_time, NULL);
	for(i=0;i<SMS4_N;i++)
	{
		r = SDF_Encrypt(hSessionHandle, hKey, uiAlgID, NULL, srcdata, SMS4_L, encdata, &enclen);
		if(r)
		{
			printf("encrypt data fail:%x\n", r);
			return r;
		}
	}
gettimeofday(&finish_time, NULL);	
enc_total_val = (finish_time.tv_sec-start_time.tv_sec)*1000000+finish_time.tv_usec - start_time.tv_usec;
#if 1
fprintf(stdout, "SMS4 ecb enc total time : %f us\n", enc_total_val);
fprintf(stdout, "SMS4 ecb enc performance: %f Mbps\n", ((double)((8*SMS4_L*SMS4_N)/((enc_total_val/1000000)*1024*1024))));
#endif
gettimeofday(&start_time, NULL);
	for(i=0;i<SMS4_N;i++)
	{
		r = SDF_Decrypt(hSessionHandle, hKey, uiAlgID, NULL, encdata, SMS4_L, dstdata, &declen);
		if(r)
		{
			printf("decrypt data fail:%x\n", r);
			return r;
		}
	}
gettimeofday(&finish_time, NULL);	
dec_total_val = (finish_time.tv_sec-start_time.tv_sec)*1000000+finish_time.tv_usec - start_time.tv_usec;
#if 1
fprintf(stdout, "SMS4 ecb dec total time : %f us\n", dec_total_val);
fprintf(stdout, "SMS4 ecb dec performance: %f Mbps\n", ((double)((8*SMS4_L*SMS4_N)/((dec_total_val/1000000)*1024*1024))));
#endif
#if 1
	//print_data("encrypt data:", encdata, enclen);

	if((enclen != declen) || memcmp(srcdata, dstdata,SMS4_L))
	{
		printf("%s()-src data != dst data\n", __func__);
		if(enclen!=declen)
		{
			printf("enclen = %d,declen=%d\n", enclen,declen);
			return 1;
		}		
		
		for(i=0;i<enclen;i++)
		{
			printf(" ",srcdata[i]);
			if(i%16==15)
				printf("\n");
		}
		for(i=0;i<declen;i++)
		{
			printf(" ",dstdata[i]);
			if(i%16==15)
				printf("\n");
		}
		return 1;
	}
#endif
	free(srcdata);
	free(encdata);
	free(dstdata);
	r = SDF_DestroyKey(hSessionHandle, hKey);
	if(r)
	{
		printf("destroy session key fail:%x\n", r);
		return r;
	} 
	//printf("%s() - success\n", __func__);
	return 0;	
}
u32 sms4_cbc_performance_test(void *hSessionHandle)
{
	u32 r,i;	
	void *hKey;
	unsigned int enclen = 0;
	unsigned int declen = 0;

	unsigned char * srcdata = malloc(SMS4_L);
	//printf("malloc ok...0\n");
	unsigned char * encdata = malloc(SMS4_L);
	//printf("malloc ok...1\n");
	unsigned char * dstdata = malloc(SMS4_L);
	//printf("malloc ok...2\n");
	u8 key[16]={0};
	u8 iv[16]={0};
	u32 uiAlgID = SGD_SMS4_CBC;

	double enc_total_val = 0;
	double dec_total_val = 0;
	
 	for(i=0;i<16;i++)
	{
		key[i] = rand();
	}
	for(i=0;i<16;i++)
	{
		iv[i] = i;
	}
 	for(i=0;i<SMS4_L;i++)
	{
		srcdata[i] = rand();
	}
#if 1
	printf("-------------------------------------------------\n");
	printf("SMS4_L = %d\n", SMS4_L);
	printf("SMS4_N = %d\n", SMS4_N);
#endif
	r = SDF_ImportKey(hSessionHandle, key, 16, &hKey);
	if(r)
	{
		printf("import session key fail:%x\n", r);
		return r;	
	}
gettimeofday(&start_time, NULL);
	for(i=0;i<SMS4_N;i++)
	{
		r = SDF_Encrypt(hSessionHandle, hKey, uiAlgID, iv, srcdata, SMS4_L, encdata, &enclen);
		if(r)
		{
			printf("encrypt data fail:%x\n", r);
			return r;
		}
	}
gettimeofday(&finish_time, NULL);	
enc_total_val = (finish_time.tv_sec-start_time.tv_sec)*1000000+finish_time.tv_usec - start_time.tv_usec;
#if 1
fprintf(stdout, "SMS4 cbc enc total time : %f us\n", enc_total_val);
fprintf(stdout, "SMS4 cbc enc performance: %f Mbps\n", ((double)((8*SMS4_L*SMS4_N)/((enc_total_val/1000000)*1024*1024))));
#endif
	for(i=0;i<16;i++)
	{
		iv[i] = i;
	}
gettimeofday(&start_time, NULL);
	for(i=0;i<SMS4_N;i++)
	{
		r = SDF_Decrypt(hSessionHandle, hKey, uiAlgID, iv, encdata, SMS4_L, dstdata, &declen);
		if(r)
		{
			printf("decrypt data fail:%x\n", r);
			return r;
		}
	}
gettimeofday(&finish_time, NULL);	
dec_total_val = (finish_time.tv_sec-start_time.tv_sec)*1000000+finish_time.tv_usec - start_time.tv_usec;
#if 1
fprintf(stdout, "SMS4 cbc dec total time : %f us\n", dec_total_val);
fprintf(stdout, "SMS4 cbc dec performance: %f Mbps\n", ((double)((8*SMS4_L*SMS4_N)/((dec_total_val/1000000)*1024*1024))));
#endif
#if 1
	//print_data("encrypt data:", encdata, enclen);

	if((enclen != declen) || memcmp(srcdata, dstdata,SMS4_L))
	{
		printf("%s()-src data != dst data\n", __func__);
		
		if(enclen!=declen)
		{
			printf("enclen = %d,declen=%d\n", enclen,declen);
			return 1;
		}		
		
		for(i=0;i<enclen;i++)
		{
			printf(" ",srcdata[i]);
			if(i%16==15)
				printf("\n");
		}
		for(i=0;i<declen;i++)
		{
			printf(" ",dstdata[i]);
			if(i%16==15)
				printf("\n");
		}
		return 1;
	}
#endif
	free(srcdata);
	free(encdata);
	free(dstdata);
	r = SDF_DestroyKey(hSessionHandle, hKey);
	if(r)
	{
		printf("destroy session key fail:%x\n", r);
		return r;
	} 
	//printf("%s() - success\n", __func__);
	return 0;	
}
u32 ssf33_ecb_performance_test(void *hSessionHandle)
{
	u32 r,i;	
	void *hKey;
	unsigned int enclen = 0;
	unsigned int declen = 0;

	unsigned char * srcdata = malloc(SSF33_L);
	//printf("malloc ok...0\n");
	unsigned char * encdata = malloc(SSF33_L);
	//printf("malloc ok...1\n");
	unsigned char * dstdata = malloc(SSF33_L);
	//printf("malloc ok...2\n");
	u8 key[16]={0};
	u32 uiAlgID = SGD_SSF33_ECB;

	double enc_total_val = 0;
	double dec_total_val = 0;
	
 	for(i=0;i<16;i++)
	{
		key[i] = rand();
	}
 	for(i=0;i<SSF33_L;i++)
	{
		srcdata[i] = rand();
	}
	
	printf("-------------------------------------------------\n");
	printf("SSF33_L = %d\n", SSF33_L);
	printf("SSF33_N = %d\n", SSF33_N);
	r = SDF_ImportKey(hSessionHandle, key, 16, &hKey);
	if(r)
	{
		printf("import session key fail:%x\n", r);
		return r;	
	}
gettimeofday(&start_time, NULL);
	for(i=0;i<SSF33_N;i++)
	{
		r = SDF_Encrypt(hSessionHandle, hKey, uiAlgID, NULL, srcdata, SSF33_L, encdata, &enclen);
		if(r)
		{
			printf("encrypt data fail:%x\n", r);
			return r;
		}
	}
gettimeofday(&finish_time, NULL);	
enc_total_val = (finish_time.tv_sec-start_time.tv_sec)*1000000+finish_time.tv_usec - start_time.tv_usec;
fprintf(stdout, "SSF33 ecb enc total time : %f us\n", enc_total_val);
fprintf(stdout, "SSF33 ecb enc performance: %f Mbps\n", ((double)((8*SSF33_L*SSF33_N)/((enc_total_val/1000000)*1024*1024))));

gettimeofday(&start_time, NULL);
	for(i=0;i<SSF33_N;i++)
	{
		r = SDF_Decrypt(hSessionHandle, hKey, uiAlgID, NULL, encdata, SSF33_L, dstdata, &declen);
		if(r)
		{
			printf("decrypt data fail:%x\n", r);
			return r;
		}
	}
gettimeofday(&finish_time, NULL);	
dec_total_val = (finish_time.tv_sec-start_time.tv_sec)*1000000+finish_time.tv_usec - start_time.tv_usec;
fprintf(stdout, "SSF33 ecb dec total time : %f us\n", dec_total_val);
fprintf(stdout, "SSF33 ecb dec performance: %f Mbps\n", ((double)((8*SSF33_L*SSF33_N)/((dec_total_val/1000000)*1024*1024))));
#if 1
	//print_data("encrypt data:", encdata, enclen);

	if((enclen != declen) || memcmp(srcdata, dstdata,SSF33_L))
	{
		printf("%s()-src data != dst data\n", __func__);
		return 1;
	}
#endif
	free(srcdata);
	free(encdata);
	free(dstdata);
	r = SDF_DestroyKey(hSessionHandle, hKey);
	if(r)
	{
		printf("destroy session key fail:%x\n", r);
		return r;
	} 
	//printf("%s() - success\n", __func__);
	return 0;	
}
u32 ssf33_cbc_performance_test(void *hSessionHandle)
{
	u32 r,i;	
	void *hKey;
	unsigned int enclen = 0;
	unsigned int declen = 0;

	unsigned char * srcdata = malloc(SSF33_L);
	//printf("malloc ok...0\n");
	unsigned char * encdata = malloc(SSF33_L);
	//printf("malloc ok...1\n");
	unsigned char * dstdata = malloc(SSF33_L);
	//printf("malloc ok...2\n");
	u8 key[16]={0};
	u8 iv[16]={0};
	u32 uiAlgID = SGD_SSF33_CBC;

	double enc_total_val = 0;
	double dec_total_val = 0;
	
 	for(i=0;i<16;i++)
	{
		key[i] = rand();
	}
	for(i=0;i<16;i++)
	{
		iv[i] = i;
	}
 	for(i=0;i<SSF33_L;i++)
	{
		srcdata[i] = rand();
	}
	
	printf("-------------------------------------------------\n");
	printf("SSF33_L = %d\n", SSF33_L);
	printf("SSF33_N = %d\n", SSF33_N);
	r = SDF_ImportKey(hSessionHandle, key, 16, &hKey);
	if(r)
	{
		printf("import session key fail:%x\n", r);
		return r;	
	}
gettimeofday(&start_time, NULL);
	for(i=0;i<SSF33_N;i++)
	{
		r = SDF_Encrypt(hSessionHandle, hKey, uiAlgID, iv, srcdata, SSF33_L, encdata, &enclen);
		if(r)
		{
			printf("encrypt data fail:%x\n", r);
			return r;
		}
	}
gettimeofday(&finish_time, NULL);	
enc_total_val = (finish_time.tv_sec-start_time.tv_sec)*1000000+finish_time.tv_usec - start_time.tv_usec;
fprintf(stdout, "SSF33 cbc enc total time : %f us\n", enc_total_val);
fprintf(stdout, "SSF33 cbc enc performance: %f Mbps\n", ((double)((8*SSF33_L*SSF33_N)/((enc_total_val/1000000)*1024*1024))));

	for(i=0;i<16;i++)
	{
		iv[i] = i;
	}
gettimeofday(&start_time, NULL);
	for(i=0;i<SSF33_N;i++)
	{
		r = SDF_Decrypt(hSessionHandle, hKey, uiAlgID, iv, encdata, SSF33_L, dstdata, &declen);
		if(r)
		{
			printf("decrypt data fail:%x\n", r);
			return r;
		}
	}
gettimeofday(&finish_time, NULL);	
dec_total_val = (finish_time.tv_sec-start_time.tv_sec)*1000000+finish_time.tv_usec - start_time.tv_usec;
fprintf(stdout, "SSF33 cbc dec total time : %f us\n", dec_total_val);
fprintf(stdout, "SSF33 cbc dec performance: %f Mbps\n", ((double)((8*SSF33_L*SSF33_N)/((dec_total_val/1000000)*1024*1024))));
#if 1
	//print_data("encrypt data:", encdata, enclen);

	if((enclen != declen) || memcmp(srcdata, dstdata,SSF33_L))
	{
		printf("%s()-src data != dst data\n", __func__);
		return 1;
	}
#endif
	free(srcdata);
	free(encdata);
	free(dstdata);
	r = SDF_DestroyKey(hSessionHandle, hKey);
	if(r)
	{
		printf("destroy session key fail:%x\n", r);
		return r;
	} 
	//printf("%s() - success\n", __func__);
	return 0;	
}
u32 sm3_performance_test(void *hSessionHandle)
{
	unsigned int i,r;
	unsigned int data_size;
	BYTE *source_data = NULL;
	BYTE enc_data[100];
	BYTE hash_soft_val[100]={0};
	int sm3_mode;
	u32 enc_len;
	u32 cnt = 0;
	double enc_total_val = 0;


	data_size = SM3_L;
	source_data = malloc(data_size);
	if(source_data==NULL)
	{
		printf("malloc error\n");
	}

	for(i=0; i<data_size; i++)
	{
		source_data[i] = rand();//i%16;
	}

	
	printf("-------------------------------------------------\n");
	printf("SM3_L = %d\n", SM3_L);
	printf("SM3_N = %d\n", SM3_N);

	sm3_mode = SGD_SM3;

//	SDF_SecLock(hSessionHandle, -1);
gettimeofday(&start_time, NULL);
	for(i=0;i<SM3_N;i++)
	{
	
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
	}
gettimeofday(&finish_time, NULL);	
//	SDF_SecUnlock(hSessionHandle);
enc_total_val = (finish_time.tv_sec-start_time.tv_sec)*1000000+finish_time.tv_usec - start_time.tv_usec;
fprintf(stdout, "SM3 total time : %f us\n", enc_total_val);
fprintf(stdout, "SM3 performance: %f Mbps\n", ((double)((8*SM3_L*SM3_N)/((enc_total_val/1000000)*1024*1024))));
	hash_soft_crypto(source_data,hash_soft_val,data_size);

	for(i=0;i<32;i++)
	{
		if(enc_data[i]!=hash_soft_val[i])
		{
			printf("hash error!\n");
			print_data("enc data", enc_data, 32);
			print_data("soft val", hash_soft_val, 32);
			return -1;
		}
	}
	printf("hash success!\n");

	printf("%s() - success\n", __func__);
	return r;
}
u32 sm2_genkey_performance_test(void *hSessionHandle)
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
	double enc_total_val = 0;

	printf("%s()-start\n", __func__);
#if 0
	for(i=1; i<3; i++)
	{
		printf("%s()-test ExportSignPublicKey\n", __func__);
		r = SDF_ExportSignPublicKey_ECC(hSessionHandle, i, &eccpubkey);
		if(r)
		{
			printf("export ecc enc public key fail:%x\n", r);
			return r;
		}
		//LOG_DATA(eccpubkey.x, ECCref_MAX_LEN);
		//LOG_DATA(eccpubkey.y, ECCref_MAX_LEN);
		
		printf("%s()-test ExportEncPublicKey\n", __func__);
		r = SDF_ExportEncPublicKey_ECC(hSessionHandle, i, &eccpubkey);
		if(r)
		{
			printf("export ecc sign public key fail:%x\n", r);
			return r;
		}
		//LOG_DATA(eccpubkey.x, ECCref_MAX_LEN);
		//LOG_DATA(eccpubkey.y, ECCref_MAX_LEN);		
	}
#endif	
	printf("-------------------------------------------------\n");
	printf("SM2_KEY_L = %d\n", SM2_KEY_L);
	printf("SM2_KEY_N = %d\n", SM2_KEY_N);
gettimeofday(&start_time, NULL);
	for(i=0;i<SM2_KEY_N;i++)
	{
		r = SDF_GenerateKeyPair_ECC(hSessionHandle, SGD_SM2_1, 256, &eccpubkey, &eccprikey);
		if(r)
		{
			printf("generate ecc key pair fail:%x\n", r);
			return r;
		}
	}
gettimeofday(&finish_time, NULL);	
enc_total_val = (finish_time.tv_sec-start_time.tv_sec)*1000000+finish_time.tv_usec - start_time.tv_usec;
fprintf(stdout, "SM2 gen key total time : %f us\n", enc_total_val);
fprintf(stdout, "SM2 gen key performance: %f \B4\CE/s\n", 1/(enc_total_val/1000000/SM2_KEY_N));
fprintf(stdout, "SM2 gen key performance: %f Mbps\n", ((double)((8*SM2_KEY_L*SM2_KEY_N)/((enc_total_val/1000000)*1024*1024))));
fprintf(stdout, "SM2 gen key performance: %f time/s\n", ((double)((SM2_KEY_N)/((enc_total_val/1000000)))));
	

	printf("%s() - success\n", __func__);
	return 0;
}
u32 rsa_genkey_performance_test(void *hSessionHandle)
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
	double enc_total_val = 0;

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
	printf("-------------------------------------------------\n");
	printf("RSA_KEY_L = %d\n", RSA_KEY_L);
	printf("RSA_KEY_N = %d\n", RSA_KEY_N);
gettimeofday(&start_time, NULL);
	for(i=0;i<RSA_KEY_N;i++)
	{
		r = SDF_GenerateKeyPair_RSA(hSessionHandle, 2048, &rsapubkey, &rsaprikey);
		if(r)
		{
			printf("generate rsa  key pair fail:%x\n", r);
			return r;		
		}
	}
gettimeofday(&finish_time, NULL);	
enc_total_val = (finish_time.tv_sec-start_time.tv_sec)*1000000+finish_time.tv_usec - start_time.tv_usec;
fprintf(stdout, "RSA gen key total time : %f us\n", enc_total_val);
fprintf(stdout, "RSA gen key performance: %f \B4\CE/s\n", 1/(enc_total_val/1000000/RSA_KEY_N));
fprintf(stdout, "RSA gen key performance: %f Mbps\n", ((double)((8*RSA_KEY_L*RSA_KEY_N)/((enc_total_val/1000000)*1024*1024))));
fprintf(stdout, "RSA gen key performance: %f time/s\n", ((double)((RSA_KEY_N)/((enc_total_val/1000000)))));
	

	printf("%s() - success\n", __func__);
	return 0;
}
u32 rsa_ext_op_performance_test(void *hSessionHandle)
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
	double enc_total_val = 0;
	double dec_total_val = 0;

	printf("%s()-start\n", __func__);

#if 1
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
#endif

	datalen = 256;
	enclen = 256;
	for(i=0; i<datalen; i++)
		data[i] = (u8)(i+0x010);
	printf("-------------------------------------------------\n");
	printf("RSA_EXT_OP_L = %d\n", RSA_EXT_OP_L);
	printf("RSA_EXT_OP_N = %d\n", RSA_EXT_OP_N);
gettimeofday(&start_time, NULL);
	for(i=0;i<RSA_EXT_OP_N;i++)
	{
		r = SDF_ExternalPublicKeyOperation_RSA(hSessionHandle, &rsapubkey, data, datalen, encdata, &enclen);
		if(r)
		{
			printf("external rsa public key operation fail:%x\n", r);
			return r;
		}
	}
gettimeofday(&finish_time, NULL);	
enc_total_val = (finish_time.tv_sec-start_time.tv_sec)*1000000+finish_time.tv_usec - start_time.tv_usec;
fprintf(stdout, "RSA external publickey op total time : %f us\n", enc_total_val);
fprintf(stdout, "RSA external publickey op performance: %f \B4\CE/s\n", RSA_EXT_OP_N/(enc_total_val/1000000));
fprintf(stdout, "RSA external publickey op performance: %f tps\n", ((double)((RSA_EXT_OP_L*RSA_EXT_OP_N)/((enc_total_val/1000000)))));
fprintf(stdout, "RSA external publickey op performance: %f time/s\n", ((double)((RSA_EXT_OP_N)/((enc_total_val/1000000)))));


	declen = 256;
gettimeofday(&start_time, NULL);
	for(i=0;i<RSA_EXT_OP_N;i++)
	{
		r = SDF_ExternalPrivateKeyOperation_RSA(hSessionHandle, &rsaprikey, encdata, enclen, decdata, &declen);
		if(r)
		{
			printf("external rsa private key operation fail:%x\n", r);
			return r;
		}
	}
gettimeofday(&finish_time, NULL);	
dec_total_val = (finish_time.tv_sec-start_time.tv_sec)*1000000+finish_time.tv_usec - start_time.tv_usec;
fprintf(stdout, "RSA external privatekey op total time : %f us\n", dec_total_val);
fprintf(stdout, "RSA external privatekey op performance: %f \B4\CE/s\n", RSA_EXT_OP_N/(dec_total_val/1000000));
fprintf(stdout, "RSA external privatekey op performance: %f tps\n", ((double)((RSA_EXT_OP_L*RSA_EXT_OP_N)/((dec_total_val/1000000)))));
fprintf(stdout, "RSA external privatekey op performance: %f time/s\n", ((double)((RSA_EXT_OP_N)/((dec_total_val/1000000)))));


	if((declen != datalen) || memcmp(data, decdata, datalen))
	{
		printf("%s()-source data != dec data\n", __func__);
		return 1;
	}

	printf("%s() - success\n", __func__);
	return 0;
	
}

u32 rsa_int_op_performance_test(void *hSessionHandle)
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
	double enc_total_val = 0;
	double dec_total_val = 0;

	printf("%s()-start\n", __func__);
	
	/*test rsa internal key operation*/
	//printf("test internal rsa pubkey operation\n");
	datalen = 256;
	enclen = 256;
	declen = 256;
	for(i=0; i<datalen; i++)
		data[i] = (u8)(i+0x10);
	printf("-------------------------------------------------\n");
	printf("RSA_INT_OP_L = %d\n", RSA_INT_OP_L);
	printf("RSA_INT_OP_N = %d\n", RSA_INT_OP_N);
gettimeofday(&start_time, NULL);
	for(i=0;i<RSA_INT_OP_N;i++)
	{
		r = SDF_InternalPublicKeyOperation_RSA(hSessionHandle, 1, data, datalen, encdata, &enclen);
		if(r)
		{
			printf("internal rsa public key operation fail:%x\n", r);
			return r;
		}
	}
gettimeofday(&finish_time, NULL);	
enc_total_val = (finish_time.tv_sec-start_time.tv_sec)*1000000+finish_time.tv_usec - start_time.tv_usec;
fprintf(stdout, "RSA internal publickey op total time : %f us\n", enc_total_val);
fprintf(stdout, "RSA internal publickey op performance: %f \B4\CE/s\n", RSA_INT_OP_N/(enc_total_val/1000000));
fprintf(stdout, "RSA internal publickey op performance: %f tps\n", ((double)((RSA_INT_OP_L*RSA_INT_OP_N)/((enc_total_val/1000000)))));
fprintf(stdout, "RSA internal publickey op performance: %f time/s\n", ((double)((RSA_INT_OP_N)/((enc_total_val/1000000)))));
	
gettimeofday(&start_time, NULL);
	for(i=0;i<RSA_INT_OP_N;i++)
	{
		r = SDF_InternalPrivateKeyOperation_RSA(hSessionHandle, 1, encdata, enclen, decdata, &declen);
		if(r)
		{
			printf("internal rsa private key operation fail:%x\n", r);
			return r;
		}
	}
gettimeofday(&finish_time, NULL);	
dec_total_val = (finish_time.tv_sec-start_time.tv_sec)*1000000+finish_time.tv_usec - start_time.tv_usec;
fprintf(stdout, "RSA internal privatekey op total time : %f us\n", dec_total_val);
fprintf(stdout, "RSA internal privatekey op performance: %f \B4\CE/s\n", RSA_INT_OP_N/(dec_total_val/1000000));
fprintf(stdout, "RSA internal privatekey op performance: %f tps\n", ((double)((RSA_INT_OP_L*RSA_INT_OP_N)/((dec_total_val/1000000)))));
fprintf(stdout, "RSA internal privatekey op performance: %f time/s\n", ((double)((RSA_INT_OP_N)/((dec_total_val/1000000)))));
	if((declen != datalen) || memcmp(data, decdata, datalen))
	{
		printf("%s()-source data != dec data\n", __func__);
		return 1;
	}
	printf("test rsa internal key operation success\n");
	return 0;
}
