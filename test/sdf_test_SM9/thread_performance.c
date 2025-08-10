#include <sdf.h>
#include <sdf_type.h>
#include <sdf_sm9.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <malloc.h>
#include <pthread.h>
#include <semaphore.h>

#define THREAD_NUM	32
#define THREAD_LOOP	4
#define SYMM_PACKET_LEN 0x8000
#define HASH_PACKET_LEN	0x8000
#define SYMM_LEN	0x100000
#define HASH_LEN	0x100000
#define SM2_LOOP_COUNT  1000
#define RSA_LOOP_COUNT  1

unsigned char *_get_sym_algo_name(unsigned int alog_type)
{
	unsigned int type;
	
	type = (alog_type & 0x80000f00);
	if(type == 0x00000100)
		return "SM1";
	else if(type == 0x00000200)
		return "SSF33";
	else if(type == 0x00000400)
		return "SM4";
	else if(type == 0x00000600)
		return "SM6";
	else if(type == 0x80000200)
		return "AES";	
	else
		return "UNKNOWN";
}

unsigned char *_get_sym_type_name(unsigned int alog_type)
{
	unsigned int type;
	
	type = (alog_type & 0x0000000f);
	if(type == 0x00000001)
		return "ECB";
	else if(type == 0x00000002)
		return "CBC";
	else if(type == 0x00000004)
		return "CFB";
	else if(type == 0x00000008)
		return "OFB";
	else if(type == 0x00000000)
		return "HASH";
	else
		return "UNKNOWN";
}

unsigned char *_get_hash_algo_name(unsigned int alog_type)
{
	unsigned int type;
	
	type = (alog_type & 0x000000ff);
	if(type == 0x00000001)
		return "SM3";
	else if(type == 0x00000002)
		return "SHA1";
	else if(type == 0x00000004)
		return "SHA256";
	else if(type == 0x00000008)
		return "SHA512";
	else if(type == 0x00000010)
		return "SHA0";
	else if(type == 0x00000020)
		return "SHA224";
	else if(type == 0x00000040)
		return "SHA384";
	else
		return "UNKNOWN";
}

struct thread_param{
	int thread_num;
	unsigned int loop_count;
	unsigned int test_bits;
	unsigned int data_len;
	unsigned char *data_buf;
	unsigned char *dst_buf;
	unsigned char key[16];
	unsigned char iv[16];
	unsigned int alg_type;
	void *hDevcieHandle;
	void *hSessionHandle;
	void *hKeyHandle;
};
struct timeval start_time, finish_time;

void *symm_enc_performance(void *arg)
{
	int i;
	u32  r;
	u32 enc_datalen;
	u8  temp_iv[16] = {0};
	struct thread_param *p_param = (struct thread_param *)arg;

//	printf("%s()-thread %d start\n", __func__, (int)(p_param->thread_num));

	for(i=0; i<THREAD_LOOP; i++)
	{
		memcpy(temp_iv, p_param->iv, 16);
		r = SDF_Encrypt(p_param->hSessionHandle, p_param->hKeyHandle, p_param->alg_type, temp_iv, p_param->data_buf, p_param->data_len, p_param->dst_buf, &enc_datalen);
		if(r)
		{
			printf("encrypt data fail:%x\n", r);
			pthread_exit((void *)r);
		}
	}

	pthread_exit((void *)r);
}

void *symm_dec_performance(void *arg)
{
	int i;
	u32  r;
	u32 enc_datalen;
	u8  temp_iv[16] = {0};
	struct thread_param *p_param = (struct thread_param *)arg;

//	printf("%s()-thread %d start\n", __func__, (int)(p_param->thread_num));

	for(i=0; i<THREAD_LOOP; i++)
	{
		memcpy(temp_iv, p_param->iv, 16);
		r = SDF_Decrypt(p_param->hSessionHandle, p_param->hKeyHandle, p_param->alg_type, temp_iv, p_param->dst_buf, p_param->data_len, p_param->dst_buf, &enc_datalen);
		if(r)
		{
			printf("encrypt data fail:%x\n", r);
			pthread_exit((void *)r);
		}
	}

	pthread_exit((void *)r);
}

int thread_test_symm_performance(int alg_type, int test_len)
{
	int i,j;
	pthread_t tid[THREAD_NUM];
	void *tret[THREAD_NUM];
	struct thread_param param[THREAD_NUM];
	double total_val = 0;
	u32  r;

	srand((unsigned int)time(NULL));

	for(i=0; i<THREAD_NUM; i++)
	{
		param[i].thread_num = i;
		param[i].alg_type = alg_type;
		param[i].data_len = test_len;
		param[i].data_buf = malloc(test_len);
		param[i].dst_buf = malloc(test_len);
		for(j=0; j<16; j++)
		{
			param[i].key[j] = (unsigned char)rand();
			param[i].iv[j] = (unsigned char)rand();
		}
		for(j=0; j<test_len; j++)
		{
			param[i].data_buf[j] = (unsigned char)rand();
		}

		r = SDF_OpenDevice(&param[i].hDevcieHandle);
		if(r)
		{
			printf("SDF_OpenDevice fail:%x\n", r);
			goto err;
		}

		r = SDF_OpenSession(param[i].hDevcieHandle, &param[i].hSessionHandle);
		if(r)
		{
			printf("SDF_OpenSession fail:%x\n", r);
			goto err;
		}

		r = EVDF_SetKey(param[i].hSessionHandle, param[i].key, 16, &param[i].hKeyHandle);
		if(r)
		{
			printf("set key fail:%x\n", r);
			goto err;	
		}
	}

	gettimeofday(&start_time, NULL);
	for(i=0; i<THREAD_NUM; i++)
	{
		
		pthread_create(&tid[i], NULL, symm_enc_performance, (void *)&param[i]);
	}

	for(i=0; i<THREAD_NUM; i++)
	{
		pthread_join(tid[i], &tret[i]);
	//	printf("thread %d exit code : %x\n", i, (int)tret[i]);
	}
	gettimeofday(&finish_time, NULL);	
	total_val = (finish_time.tv_sec-start_time.tv_sec)*1000000+finish_time.tv_usec - start_time.tv_usec;
//	fprintf(stdout, "%s %s enc total time : %f us\n", _get_sym_algo_name(alg_type), _get_sym_type_name(alg_type), total_val);
	fprintf(stdout, "%s %s enc performance: %f Mbps\n", _get_sym_algo_name(alg_type), _get_sym_type_name(alg_type), ((double)((8*THREAD_NUM*test_len*THREAD_LOOP)/((total_val/1000000)*1024*1024))));


	gettimeofday(&start_time, NULL);
	for(i=0; i<THREAD_NUM; i++)
	{
		
		pthread_create(&tid[i], NULL, symm_dec_performance, (void *)&param[i]);
	}

	for(i=0; i<THREAD_NUM; i++)
	{
		pthread_join(tid[i], &tret[i]);
	//	printf("thread %d exit code : %x\n", i, (int)tret[i]);
	}
	gettimeofday(&finish_time, NULL);	
	total_val = (finish_time.tv_sec-start_time.tv_sec)*1000000+finish_time.tv_usec - start_time.tv_usec;
//	fprintf(stdout, "%s %s dec total time : %f us\n", _get_sym_algo_name(alg_type), _get_sym_type_name(alg_type), total_val);
	fprintf(stdout, "%s %s dec performance: %f Mbps\n", _get_sym_algo_name(alg_type), _get_sym_type_name(alg_type), ((double)((8*THREAD_NUM*test_len*THREAD_LOOP)/((total_val/1000000)*1024*1024))));

err:
	for(i=0; i<THREAD_NUM; i++)
	{
		r = SDF_DestroyKey(param[i].hSessionHandle,param[i].hKeyHandle);
		if(r)
		{
			printf("destroy session key fail:%x\n", r);
			return r;
		}

		if(param[i].hSessionHandle)
			SDF_CloseSession(param[i].hSessionHandle);
		if(param[i].hDevcieHandle)
			SDF_CloseDevice(param[i].hDevcieHandle);	
		free(param[i].data_buf);
		free(param[i].dst_buf);
	}

	return 0;
}


void *hash_performance(void *arg)
{
	int i;
	u32  r;
	u32 enc_datalen;
	struct thread_param *p_param = (struct thread_param *)arg;

//	printf("%s()-thread %d start\n", __func__, (int)(p_param->thread_num));

	for(i=0; i<THREAD_LOOP; i++)
	{
		r = SDF_HashInit(p_param->hSessionHandle, p_param->alg_type, NULL, NULL, 0);
		if(r)
		{
			printf("SDF_HashInit error 0x%x\n", r);
		}

		r = SDF_HashUpdate(p_param->hSessionHandle, p_param->data_buf, p_param->data_len);
		if(r)
		{
			printf("SDF_HashUpdate error 0x%x\n", r);
		}

		enc_datalen = 100;
		r = SDF_HashFinal(p_param->hSessionHandle, p_param->dst_buf , &enc_datalen);
		if(r)
		{
			printf("SDF_HashFinal error 0x%x\n", r);
		}
	}

	pthread_exit((void *)r);
}


int thread_test_hash_performance(int alg_type, int test_len)
{
	int i,j;
	pthread_t tid[THREAD_NUM];
	void *tret[THREAD_NUM];
	struct thread_param param[THREAD_NUM];
	double total_val = 0;
	u32  r;

	srand((unsigned int)time(NULL));

	for(i=0; i<THREAD_NUM; i++)
	{
		param[i].thread_num = i;
		param[i].alg_type = alg_type;
		param[i].data_len = test_len;
		param[i].data_buf = malloc(test_len);
		param[i].dst_buf = malloc(test_len);
		for(j=0; j<test_len; j++)
		{
			param[i].data_buf[j] = (unsigned char)rand();
		}

		r = SDF_OpenDevice(&param[i].hDevcieHandle);
		if(r)
		{
			printf("SDF_OpenDevice fail:%x\n", r);
			goto err;
		}

		r = SDF_OpenSession(param[i].hDevcieHandle, &param[i].hSessionHandle);
		if(r)
		{
			printf("SDF_OpenSession fail:%x\n", r);
			goto err;
		}
	}

	gettimeofday(&start_time, NULL);
	for(i=0; i<THREAD_NUM; i++)
	{
		
		pthread_create(&tid[i], NULL, hash_performance, (void *)&param[i]);
	}

	for(i=0; i<THREAD_NUM; i++)
	{
		pthread_join(tid[i], &tret[i]);
	//	printf("thread %d exit code : %x\n", i, (int)tret[i]);
	}
	gettimeofday(&finish_time, NULL);	
	total_val = (finish_time.tv_sec-start_time.tv_sec)*1000000+finish_time.tv_usec - start_time.tv_usec;
//	fprintf(stdout, "%s %s enc total time : %f us\n", _get_sym_algo_name(alg_type), _get_sym_type_name(alg_type), total_val);
	fprintf(stdout, "%s performance: %f Mbps\n", _get_hash_algo_name(alg_type), ((double)((8*THREAD_NUM*test_len*THREAD_LOOP)/((total_val/1000000)*1024*1024))));	

err:
	for(i=0; i<THREAD_NUM; i++)
	{
		if(param[i].hSessionHandle)
			SDF_CloseSession(param[i].hSessionHandle);
		if(param[i].hDevcieHandle)
			SDF_CloseDevice(param[i].hDevcieHandle);	
		free(param[i].data_buf);
		free(param[i].dst_buf);
	}

	return 0;
}


void *sm2_genkey_performance(void *arg)
{
	int i;
	u32  r;
	struct thread_param *p_param = (struct thread_param *)arg;
	ECCrefPublicKey eccpubkey;
	ECCrefPrivateKey eccprikey;

//	printf("%s()-thread %d start\n", __func__, (int)(p_param->thread_num));

	for(i=0; i<p_param->loop_count; i++)
	{
		r = SDF_GenerateKeyPair_ECC(p_param->hSessionHandle, p_param->alg_type, 256, &eccpubkey, &eccprikey);
		if(r)
		{
			printf("generate ecc key pair fail:%x\n", r);
			return r;
		}
	}

	pthread_exit((void *)r);
}


int thread_test_sm2_genkey_performance(int alg_type, int loop_count)
{
	int i,j;
	pthread_t tid[THREAD_NUM];
	void *tret[THREAD_NUM];
	struct thread_param param[THREAD_NUM];
	double total_val = 0;
	u32  r;

	srand((unsigned int)time(NULL));

	for(i=0; i<THREAD_NUM; i++)
	{
		param[i].thread_num = i;
		param[i].alg_type = alg_type;
		param[i].loop_count = loop_count;
		r = SDF_OpenDevice(&param[i].hDevcieHandle);
		if(r)
		{
			printf("SDF_OpenDevice fail:%x\n", r);
			goto err;
		}

		r = SDF_OpenSession(param[i].hDevcieHandle, &param[i].hSessionHandle);
		if(r)
		{
			printf("SDF_OpenSession fail:%x\n", r);
			goto err;
		}
	}

	gettimeofday(&start_time, NULL);
	for(i=0; i<THREAD_NUM; i++)
	{
		
		pthread_create(&tid[i], NULL, sm2_genkey_performance, (void *)&param[i]);
	}

	for(i=0; i<THREAD_NUM; i++)
	{
		pthread_join(tid[i], &tret[i]);
	//	printf("thread %d exit code : %x\n", i, (int)tret[i]);
	}
	gettimeofday(&finish_time, NULL);	
	total_val = (finish_time.tv_sec-start_time.tv_sec)*1000000+finish_time.tv_usec - start_time.tv_usec;
//	fprintf(stdout, "SM2 gen key total time : %f us\n", total_val);
	fprintf(stdout, "SM2 gen key performance: %f times/s\n", (double)((THREAD_NUM*loop_count)/(total_val/1000000)));	

err:
	for(i=0; i<THREAD_NUM; i++)
	{
		if(param[i].hSessionHandle)
			SDF_CloseSession(param[i].hSessionHandle);
		if(param[i].hDevcieHandle)
			SDF_CloseDevice(param[i].hDevcieHandle);	
	}

	return 0;
}


void *sm2_int_sign_performance(void *arg)
{
	int i;
	u32  r;
	struct thread_param *p_param = (struct thread_param *)arg;
	unsigned char data[32] = {
		0x60,0x53,0x28,0x50,0x81,0xE6,0x56,0x3C,0x2C,0x32,0x15,0x15,0x9B,0x75,0xBE,0x59,
		0xF7,0x04,0x1D,0x12,0x98,0x6B,0xB8,0x4E,0xB1,0x7E,0x75,0xA9,0x96,0x10,0xF5,0x25
	};	

//	printf("%s()-thread %d start\n", __func__, (int)(p_param->thread_num));


	for(i=0; i<p_param->loop_count; i++)
	{
		r = SDF_InternalSign_ECC(p_param->hSessionHandle, 1, data, 32, (ECCSignature *)p_param->data_buf);
		if(r)
		{
			printf("internal ecc sign fail:%x\n", r);
			return r;
		}
	}

	pthread_exit((void *)r);
}


void *sm2_int_verify_performance(void *arg)
{
	int i;
	u32  r;
	struct thread_param *p_param = (struct thread_param *)arg;
	unsigned char data[32] = {
		0x60,0x53,0x28,0x50,0x81,0xE6,0x56,0x3C,0x2C,0x32,0x15,0x15,0x9B,0x75,0xBE,0x59,
		0xF7,0x04,0x1D,0x12,0x98,0x6B,0xB8,0x4E,0xB1,0x7E,0x75,0xA9,0x96,0x10,0xF5,0x25
	};

//	printf("%s()-thread %d start\n", __func__, (int)(p_param->thread_num));

	for(i=0; i<p_param->loop_count; i++)
	{
		r = SDF_InternalVerify_ECC(p_param->hSessionHandle, 1, data, 32, (ECCSignature *)p_param->data_buf);
		if(r)
		{
			printf("external ecc verify fail:%x\n", r);
			return r;
		}
	}

	pthread_exit((void *)r);
}


int thread_test_sm2_int_sign_verify_performance(int alg_type, int loop_count)
{
	int i,j;
	pthread_t tid[THREAD_NUM];
	void *tret[THREAD_NUM];
	struct thread_param param[THREAD_NUM];
	double total_val = 0;
	u32  r;

	srand((unsigned int)time(NULL));
/*
	r = SDF_OpenDevice(&param[0].hDevcieHandle);
	if(r)
	{
		printf("SDF_OpenDevice fail:%x\n", r);
		goto err;
	}
*/
	for(i=0; i<THREAD_NUM; i++)
	{
		param[i].thread_num = i;
		param[i].alg_type = alg_type;
		param[i].loop_count = loop_count;
		param[i].data_buf = malloc(sizeof(ECCSignature));

		r = SDF_OpenDevice(&param[i].hDevcieHandle);
		if(r)
		{
			printf("SDF_OpenDevice fail:%x\n", r);
			goto err;
		}

		r = SDF_OpenSession(param[i].hDevcieHandle, &param[i].hSessionHandle);
		if(r)
		{
			printf("SDF_OpenSession fail:%x\n", r);
			goto err;
		}

		r = SDF_GetPrivateKeyAccessRight(param[i].hSessionHandle, 1, "11111111", 8);
		if(r)
		{
			printf("SDF_GetPrivateKeyAccessRight fail:%x\n", r);
			goto err;
		}
	}

	gettimeofday(&start_time, NULL);
	for(i=0; i<THREAD_NUM; i++)
	{
		
		pthread_create(&tid[i], NULL, sm2_int_sign_performance, (void *)&param[i]);
	}

	for(i=0; i<THREAD_NUM; i++)
	{
		pthread_join(tid[i], &tret[i]);
	//	printf("thread %d exit code : %x\n", i, (int)tret[i]);
	}
	gettimeofday(&finish_time, NULL);	
	total_val = (finish_time.tv_sec-start_time.tv_sec)*1000000+finish_time.tv_usec - start_time.tv_usec;
//	fprintf(stdout, "SM2 gen key total time : %f us\n", total_val);
	fprintf(stdout, "SM2 int sign performance: %f times/s\n", (double)((THREAD_NUM*loop_count)/(total_val/1000000)));	

	gettimeofday(&start_time, NULL);
	for(i=0; i<THREAD_NUM; i++)
	{
		
		pthread_create(&tid[i], NULL, sm2_int_verify_performance, (void *)&param[i]);
	}

	for(i=0; i<THREAD_NUM; i++)
	{
		pthread_join(tid[i], &tret[i]);
	//	printf("thread %d exit code : %x\n", i, (int)tret[i]);
	}
	gettimeofday(&finish_time, NULL);	
	total_val = (finish_time.tv_sec-start_time.tv_sec)*1000000+finish_time.tv_usec - start_time.tv_usec;
//	fprintf(stdout, "SM2 gen key total time : %f us\n", total_val);
	fprintf(stdout, "SM2 int verify performance: %f times/s\n", (double)((THREAD_NUM*loop_count)/(total_val/1000000)));

err:
	for(i=0; i<THREAD_NUM; i++)
	{
		if(param[i].hSessionHandle)
			SDF_CloseSession(param[i].hSessionHandle);
		if(param[i].hDevcieHandle)
			SDF_CloseDevice(param[i].hDevcieHandle);	
		free(param[i].data_buf);
	}
/*	
	if(param[0].hDevcieHandle)
		SDF_CloseDevice(param[i].hDevcieHandle);	
*/
	return 0;
}


void *sm2_int_enc_performance(void *arg)
{
	int i;
	u32  r;
	struct thread_param *p_param = (struct thread_param *)arg;
	ECCrefPublicKey eccpubkey;
	ECCrefPrivateKey eccprikey;
	ECCCipher *pecccipher = (ECCCipher *)p_param->dst_buf;

//	printf("%s()-thread %d start\n", __func__, (int)(p_param->thread_num));

	for(i=0; i<p_param->loop_count; i++)
	{
		r = SDF_InternalEncrypt_ECC(p_param->hSessionHandle, 1, p_param->data_buf, p_param->data_len, pecccipher);
		if(r)
		{
			printf("external ecc encrypt fail:%x\n", r);
			return r;
		}
	}

	pthread_exit((void *)r);
}


void *sm2_int_dec_performance(void *arg)
{
	int i;
	u32  r;
	struct thread_param *p_param = (struct thread_param *)arg;
	int declen;
	ECCrefPrivateKey eccprikey;
	ECCCipher *pecccipher = (ECCCipher *)p_param->dst_buf;
	
	for(i=0; i<p_param->loop_count; i++)
	{
		declen = 256;
		r = SDF_InternalDecrypt_ECC(p_param->hSessionHandle, 1, pecccipher, p_param->data_buf, &declen);
		if(r)
		{
			printf("external ecc decrypt fail:%x\n", r);
			return r;			
		}
	}

	pthread_exit((void *)r);
}


int thread_test_sm2_int_enc_dec_performance(int alg_type, int loop_count, int test_len)
{
	int i,j;
	pthread_t tid[THREAD_NUM];
	void *tret[THREAD_NUM];
	struct thread_param param[THREAD_NUM];
	double total_val = 0;
	u32  r;

	srand((unsigned int)time(NULL));

	for(i=0; i<THREAD_NUM; i++)
	{
		param[i].thread_num = i;
		param[i].alg_type = alg_type;
		param[i].loop_count = loop_count;
		param[i].data_len = test_len;
		param[i].data_buf = malloc(test_len);
		param[i].dst_buf = malloc(test_len+0x200);
		for(j=0; j<test_len; j++)
		{
			param[i].data_buf[j] = (unsigned char)rand();
		}
		r = SDF_OpenDevice(&param[i].hDevcieHandle);
		if(r)
		{
			printf("SDF_OpenDevice fail:%x\n", r);
			goto err;
		}

		r = SDF_OpenSession(param[i].hDevcieHandle, &param[i].hSessionHandle);
		if(r)
		{
			printf("SDF_OpenSession fail:%x\n", r);
			goto err;
		}
		
		r = SDF_GetPrivateKeyAccessRight(param[i].hSessionHandle, 1, "11111111", 8);
		if(r)
		{
			printf("SDF_GetPrivateKeyAccessRight fail:%x\n", r);
			goto err;
		}		
	}

	gettimeofday(&start_time, NULL);
	for(i=0; i<THREAD_NUM; i++)
	{
		
		pthread_create(&tid[i], NULL, sm2_int_enc_performance, (void *)&param[i]);
	}

	for(i=0; i<THREAD_NUM; i++)
	{
		pthread_join(tid[i], &tret[i]);
	//	printf("thread %d exit code : %x\n", i, (int)tret[i]);
	}
	gettimeofday(&finish_time, NULL);	
	total_val = (finish_time.tv_sec-start_time.tv_sec)*1000000+finish_time.tv_usec - start_time.tv_usec;
//	fprintf(stdout, "SM2 gen key total time : %f us\n", total_val);
	fprintf(stdout, "SM2 int enc performance: %f times/s\n", (double)((THREAD_NUM*loop_count)/(total_val/1000000)));	

	gettimeofday(&start_time, NULL);
	for(i=0; i<THREAD_NUM; i++)
	{
		
		pthread_create(&tid[i], NULL, sm2_int_dec_performance, (void *)&param[i]);
	}

	for(i=0; i<THREAD_NUM; i++)
	{
		pthread_join(tid[i], &tret[i]);
	//	printf("thread %d exit code : %x\n", i, (int)tret[i]);
	}
	gettimeofday(&finish_time, NULL);	
	total_val = (finish_time.tv_sec-start_time.tv_sec)*1000000+finish_time.tv_usec - start_time.tv_usec;
//	fprintf(stdout, "SM2 gen key total time : %f us\n", total_val);
	fprintf(stdout, "SM2 int dec performance: %f times/s\n", (double)((THREAD_NUM*loop_count)/(total_val/1000000)));

err:
	for(i=0; i<THREAD_NUM; i++)
	{
		if(param[i].hSessionHandle)
			SDF_CloseSession(param[i].hSessionHandle);
		if(param[i].hDevcieHandle)
			SDF_CloseDevice(param[i].hDevcieHandle);	
		free(param[i].data_buf);
		free(param[i].dst_buf);
	}

	return 0;
}


void *sm2_ext_sign_performance(void *arg)
{
	int i;
	u32  r;
	struct thread_param *p_param = (struct thread_param *)arg;
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

//	printf("%s()-thread %d start\n", __func__, (int)(p_param->thread_num));

	memset(&eccprikey, 0, sizeof(ECCrefPrivateKey));
	memcpy(eccprikey.K+32, keypair+64, 32);
	eccprikey.bits = 256;
	for(i=0; i<32; i++)
		data[i] = (u8)(i+0x80);

	for(i=0; i<p_param->loop_count; i++)
	{
		r = SDF_ExternalSign_ECC(p_param->hSessionHandle, p_param->alg_type, &eccprikey, data, 32, &sig);
		if(r)
		{
			printf("external ecc sign fail:%x\n", r);
			return r;
		}
	}

	pthread_exit((void *)r);
}


void *sm2_ext_verify_performance(void *arg)
{
	int i;
	u32  r;
	struct thread_param *p_param = (struct thread_param *)arg;
	ECCrefPublicKey eccpubkey;
	ECCrefPrivateKey eccprikey;
	ECCSignature sig;
	u8 keypair[] ={
		0xAA,0xC2,0xAB,0x60,0x09,0xA3,0x41,0xB5,0xE9,0xCA,0xE8,0x02,0x9D,0xC9,0x6B,0x15,
		0x1A,0xE0,0x9B,0x1F,0x69,0x4A,0xBD,0x7A,0xC6,0xBD,0xF5,0xB4,0xD9,0x7C,0x4B,0x77,
		0xE4,0x51,0x88,0x49,0x2A,0x11,0x6E,0x7C,0x3A,0xD4,0xE2,0xF5,0x6C,0x4F,0x20,0xA2,
		0xB5,0x64,0x6F,0x19,0x85,0xC9,0x41,0xC6,0x55,0x71,0x0F,0x99,0x21,0xA1,0x5A,0x70
	};
	unsigned char hash[32] = {
		0x60,0x53,0x28,0x50,0x81,0xE6,0x56,0x3C,0x2C,0x32,0x15,0x15,0x9B,0x75,0xBE,0x59,
		0xF7,0x04,0x1D,0x12,0x98,0x6B,0xB8,0x4E,0xB1,0x7E,0x75,0xA9,0x96,0x10,0xF5,0x25
	};
	unsigned char rs[64] = {
		0xDC,0x67,0x0F,0xE5,0xEE,0x25,0x45,0xDD,0xD5,0xC7,0xF4,0xD5,0x1B,0xDE,0xD1,0xA9,
		0xE0,0x58,0x0A,0x23,0x7C,0xE9,0x5E,0x61,0xDC,0x75,0xC9,0x7F,0x70,0x83,0x26,0xF3,
		0x33,0xCA,0xE8,0xE9,0x59,0xFD,0xC5,0xEF,0x20,0x83,0xF0,0x49,0xD8,0x3E,0x83,0x90,
		0x04,0x21,0x7F,0xBA,0xD2,0xEA,0xC6,0xDC,0x48,0xB8,0xF2,0x3F,0x6C,0xF4,0x97,0x35};

//	printf("%s()-thread %d start\n", __func__, (int)(p_param->thread_num));

	memset(&eccpubkey, 0, sizeof(ECCrefPublicKey));
	memcpy(eccpubkey.x+32, keypair, 32);
	memcpy(eccpubkey.y+32, keypair+32, 32);
	eccpubkey.bits = 256;
	memcpy(&sig.r[32],rs,32);
	memcpy(&sig.s[32],rs+32,32);

	for(i=0; i<p_param->loop_count; i++)
	{
		r = SDF_ExternalVerify_ECC(p_param->hSessionHandle, p_param->alg_type, &eccpubkey, hash, 32, &sig);
		if(r)
		{
			printf("external ecc verify fail:%x\n", r);
			return r;
		}
	}

	pthread_exit((void *)r);
}


int thread_test_sm2_ext_sign_verify_performance(int alg_type, int loop_count)
{
	int i,j;
	pthread_t tid[THREAD_NUM];
	void *tret[THREAD_NUM];
	struct thread_param param[THREAD_NUM];
	double total_val = 0;
	u32  r;

	srand((unsigned int)time(NULL));

	for(i=0; i<THREAD_NUM; i++)
	{
		param[i].thread_num = i;
		param[i].alg_type = alg_type;
		param[i].loop_count = loop_count;
		r = SDF_OpenDevice(&param[i].hDevcieHandle);
		if(r)
		{
			printf("SDF_OpenDevice fail:%x\n", r);
			goto err;
		}

		r = SDF_OpenSession(param[i].hDevcieHandle, &param[i].hSessionHandle);
		if(r)
		{
			printf("SDF_OpenSession fail:%x\n", r);
			goto err;
		}
	}

	gettimeofday(&start_time, NULL);
	for(i=0; i<THREAD_NUM; i++)
	{
		
		pthread_create(&tid[i], NULL, sm2_ext_sign_performance, (void *)&param[i]);
	}

	for(i=0; i<THREAD_NUM; i++)
	{
		pthread_join(tid[i], &tret[i]);
	//	printf("thread %d exit code : %x\n", i, (int)tret[i]);
	}
	gettimeofday(&finish_time, NULL);	
	total_val = (finish_time.tv_sec-start_time.tv_sec)*1000000+finish_time.tv_usec - start_time.tv_usec;
//	fprintf(stdout, "SM2 gen key total time : %f us\n", total_val);
	fprintf(stdout, "SM2 ext sign performance: %f times/s\n", (double)((THREAD_NUM*loop_count)/(total_val/1000000)));	

	gettimeofday(&start_time, NULL);
	for(i=0; i<THREAD_NUM; i++)
	{
		
		pthread_create(&tid[i], NULL, sm2_ext_verify_performance, (void *)&param[i]);
	}

	for(i=0; i<THREAD_NUM; i++)
	{
		pthread_join(tid[i], &tret[i]);
	//	printf("thread %d exit code : %x\n", i, (int)tret[i]);
	}
	gettimeofday(&finish_time, NULL);	
	total_val = (finish_time.tv_sec-start_time.tv_sec)*1000000+finish_time.tv_usec - start_time.tv_usec;
//	fprintf(stdout, "SM2 gen key total time : %f us\n", total_val);
	fprintf(stdout, "SM2 ext verify performance: %f times/s\n", (double)((THREAD_NUM*loop_count)/(total_val/1000000)));

err:
	for(i=0; i<THREAD_NUM; i++)
	{
		if(param[i].hSessionHandle)
			SDF_CloseSession(param[i].hSessionHandle);
		if(param[i].hDevcieHandle)
			SDF_CloseDevice(param[i].hDevcieHandle);	
	}

	return 0;
}


void *sm2_ext_enc_performance(void *arg)
{
	int i;
	u32  r;
	struct thread_param *p_param = (struct thread_param *)arg;
	ECCrefPublicKey eccpubkey;
	ECCrefPrivateKey eccprikey;
	ECCCipher *pecccipher = (ECCCipher *)p_param->dst_buf;
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

//	printf("%s()-thread %d start\n", __func__, (int)(p_param->thread_num));

	memset(&eccpubkey, 0, sizeof(ECCrefPublicKey));
	memcpy(eccpubkey.x+32, keypair, 32);
	memcpy(eccpubkey.y+32, keypair+32, 32);
	eccpubkey.bits = 256;

	for(i=0; i<p_param->loop_count; i++)
	{
		r = SDF_ExternalEncrypt_ECC(p_param->hSessionHandle, p_param->alg_type, &eccpubkey, p_param->data_buf, p_param->data_len, pecccipher);
		if(r)
		{
			printf("external ecc encrypt fail:%x\n", r);
			return r;
		}
	}

	pthread_exit((void *)r);
}


void *sm2_ext_dec_performance(void *arg)
{
	int i;
	u32  r;
	struct thread_param *p_param = (struct thread_param *)arg;
	int declen;
	ECCrefPrivateKey eccprikey;
	ECCCipher *pecccipher = (ECCCipher *)p_param->dst_buf;
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

//	printf("%s()-thread %d start\n", __func__, (int)(p_param->thread_num));

	memset(&eccprikey, 0, sizeof(ECCrefPrivateKey));
	memcpy(eccprikey.K+32, keypair+64, 32);
	eccprikey.bits = 256;
	
	for(i=0; i<p_param->loop_count; i++)
	{
		declen = 256;
		r = SDF_ExternalDecrypt_ECC(p_param->hSessionHandle, p_param->alg_type, &eccprikey, pecccipher, p_param->data_buf, &declen);
		if(r)
		{
			printf("external ecc decrypt fail:%x\n", r);
			return r;			
		}
	}

	pthread_exit((void *)r);
}


int thread_test_sm2_ext_enc_dec_performance(int alg_type, int loop_count, int test_len)
{
	int i,j;
	pthread_t tid[THREAD_NUM];
	void *tret[THREAD_NUM];
	struct thread_param param[THREAD_NUM];
	double total_val = 0;
	u32  r;

	srand((unsigned int)time(NULL));

	for(i=0; i<THREAD_NUM; i++)
	{
		param[i].thread_num = i;
		param[i].alg_type = alg_type;
		param[i].loop_count = loop_count;
		param[i].data_len = test_len;
		param[i].data_buf = malloc(test_len);
		param[i].dst_buf = malloc(test_len+0x200);
		for(j=0; j<test_len; j++)
		{
			param[i].data_buf[j] = (unsigned char)rand();
		}
		r = SDF_OpenDevice(&param[i].hDevcieHandle);
		if(r)
		{
			printf("SDF_OpenDevice fail:%x\n", r);
			goto err;
		}

		r = SDF_OpenSession(param[i].hDevcieHandle, &param[i].hSessionHandle);
		if(r)
		{
			printf("SDF_OpenSession fail:%x\n", r);
			goto err;
		}
	}

	gettimeofday(&start_time, NULL);
	for(i=0; i<THREAD_NUM; i++)
	{
		
		pthread_create(&tid[i], NULL, sm2_ext_enc_performance, (void *)&param[i]);
	}

	for(i=0; i<THREAD_NUM; i++)
	{
		pthread_join(tid[i], &tret[i]);
	//	printf("thread %d exit code : %x\n", i, (int)tret[i]);
	}
	gettimeofday(&finish_time, NULL);	
	total_val = (finish_time.tv_sec-start_time.tv_sec)*1000000+finish_time.tv_usec - start_time.tv_usec;
//	fprintf(stdout, "SM2 gen key total time : %f us\n", total_val);
	fprintf(stdout, "SM2 ext enc performance: %f times/s\n", (double)((THREAD_NUM*loop_count)/(total_val/1000000)));	

	gettimeofday(&start_time, NULL);
	for(i=0; i<THREAD_NUM; i++)
	{
		
		pthread_create(&tid[i], NULL, sm2_ext_dec_performance, (void *)&param[i]);
	}

	for(i=0; i<THREAD_NUM; i++)
	{
		pthread_join(tid[i], &tret[i]);
	//	printf("thread %d exit code : %x\n", i, (int)tret[i]);
	}
	gettimeofday(&finish_time, NULL);	
	total_val = (finish_time.tv_sec-start_time.tv_sec)*1000000+finish_time.tv_usec - start_time.tv_usec;
//	fprintf(stdout, "SM2 gen key total time : %f us\n", total_val);
	fprintf(stdout, "SM2 ext dec performance: %f times/s\n", (double)((THREAD_NUM*loop_count)/(total_val/1000000)));

err:
	for(i=0; i<THREAD_NUM; i++)
	{
		if(param[i].hSessionHandle)
			SDF_CloseSession(param[i].hSessionHandle);
		if(param[i].hDevcieHandle)
			SDF_CloseDevice(param[i].hDevcieHandle);	
		free(param[i].data_buf);
		free(param[i].dst_buf);
	}

	return 0;
}


void *rsa_genkey_performance(void *arg)
{
	int i;
	u32  r;
	struct thread_param *p_param = (struct thread_param *)arg;
	RSArefPublicKey rsapubkey;
	RSArefPrivateKey rsaprikey;

//	printf("%s()-thread %d start\n", __func__, (int)(p_param->thread_num));

	for(i=0; i<p_param->loop_count; i++)
	{
		r = SDF_GenerateKeyPair_RSA(p_param->hSessionHandle, p_param->test_bits, &rsapubkey, &rsaprikey);
		if(r)
		{
			printf("generate rsa  key pair fail:%x\n", r);
			return r;		
		}
	}

	pthread_exit((void *)r);
}


int thread_test_rsa_genkey_performance(int alg_type, int loop_count, int test_bits)
{
	int i,j;
	pthread_t tid[THREAD_NUM];
	void *tret[THREAD_NUM];
	struct thread_param param[THREAD_NUM];
	double total_val = 0;
	u32  r;

	srand((unsigned int)time(NULL));

	for(i=0; i<THREAD_NUM; i++)
	{
		param[i].thread_num = i;
		param[i].test_bits = test_bits;
		param[i].alg_type = alg_type;
		param[i].loop_count = loop_count;
		r = SDF_OpenDevice(&param[i].hDevcieHandle);
		if(r)
		{
			printf("SDF_OpenDevice fail:%x\n", r);
			goto err;
		}

		r = SDF_OpenSession(param[i].hDevcieHandle, &param[i].hSessionHandle);
		if(r)
		{
			printf("SDF_OpenSession fail:%x\n", r);
			goto err;
		}
	}

	gettimeofday(&start_time, NULL);
	for(i=0; i<THREAD_NUM; i++)
	{
		
		pthread_create(&tid[i], NULL, rsa_genkey_performance, (void *)&param[i]);
	}

	for(i=0; i<THREAD_NUM; i++)
	{
		pthread_join(tid[i], &tret[i]);
	//	printf("thread %d exit code : %x\n", i, (int)tret[i]);
	}
	gettimeofday(&finish_time, NULL);	
	total_val = (finish_time.tv_sec-start_time.tv_sec)*1000000+finish_time.tv_usec - start_time.tv_usec;
//	fprintf(stdout, "SM2 gen key total time : %f us\n", total_val);
	fprintf(stdout, "RSA%d gen key performance: %f times/s\n", test_bits, (double)((THREAD_NUM*loop_count)/(total_val/1000000)));	

err:
	for(i=0; i<THREAD_NUM; i++)
	{
		if(param[i].hSessionHandle)
			SDF_CloseSession(param[i].hSessionHandle);
		if(param[i].hDevcieHandle)
			SDF_CloseDevice(param[i].hDevcieHandle);	
	}

	return 0;
}


static RSArefPublicKey s_rsapubkey;
static RSArefPrivateKey s_rsaprikey;

void *rsa_ext_enc_performance(void *arg)
{
	int i;
	u32  r;
	struct thread_param *p_param = (struct thread_param *)arg;
	unsigned int enclen;
	
//	printf("%s()-thread %d start\n", __func__, (int)(p_param->thread_num));

	for(i=0; i<p_param->loop_count; i++)
	{
		enclen = 256;
		r = SDF_ExternalPublicKeyOperation_RSA(p_param->hSessionHandle, &s_rsapubkey, p_param->data_buf, p_param->test_bits/8, p_param->dst_buf, &enclen);
		if(r)
		{
			printf("external rsa public key operation fail:%x\n", r);
			return r;
		}
	}

	pthread_exit((void *)r);
}

void *rsa_ext_dec_performance(void *arg)
{
	int i;
	u32  r;
	struct thread_param *p_param = (struct thread_param *)arg;
	unsigned int declen;
	
//	printf("%s()-thread %d start\n", __func__, (int)(p_param->thread_num));

	for(i=0; i<p_param->loop_count; i++)
	{
		declen = 256;
		r = SDF_ExternalPrivateKeyOperation_RSA(p_param->hSessionHandle, &s_rsaprikey, p_param->dst_buf, p_param->test_bits/8, p_param->dst_buf, &declen);
		if(r)
		{
			printf("external rsa private key operation fail:%x\n", r);
			return r;
		}
	}

	pthread_exit((void *)r);
}

int thread_test_rsa_ext_enc_dec_performance(int alg_type, int loop_count, int test_bits)
{
	int i,j;
	pthread_t tid[THREAD_NUM];
	void *tret[THREAD_NUM];
	struct thread_param param[THREAD_NUM];
	double total_val = 0;
	u32  r;
	void *hDevcieHandle = NULL;
	void *hSessionHandle = NULL;

	srand((unsigned int)time(NULL));

	r = SDF_OpenDevice(&hDevcieHandle);
	if(r)
	{
		printf("SDF_OpenDevice fail:%x\n", r);
		goto err;
	}

	r = SDF_OpenSession(hDevcieHandle, &hSessionHandle);
	if(r)
	{
		printf("SDF_OpenSession fail:%x\n", r);
		goto err;
	}

	r = SDF_GenerateKeyPair_RSA(hSessionHandle, test_bits, &s_rsapubkey, &s_rsaprikey);
	if(r)
	{
		printf("generate rsa  key pair fail:%x\n", r);
		return r;		
	}

	if(hSessionHandle)
		SDF_CloseSession(hSessionHandle);
	if(hDevcieHandle)
		SDF_CloseDevice(hDevcieHandle);


	for(i=0; i<THREAD_NUM; i++)
	{
		param[i].thread_num = i;
		param[i].alg_type = alg_type;
		param[i].loop_count = loop_count;
		param[i].test_bits = test_bits;
		param[i].data_buf = malloc(test_bits);
		param[i].dst_buf = malloc(test_bits+0x200);
		for(j=0; j<test_bits/8; j++)
		{
			param[i].data_buf[j] = (unsigned char)rand();
		}
		param[i].data_buf[test_bits/8-1] = 0x00;

		r = SDF_OpenDevice(&param[i].hDevcieHandle);
		if(r)
		{
			printf("SDF_OpenDevice fail:%x\n", r);
			goto err;
		}

		r = SDF_OpenSession(param[i].hDevcieHandle, &param[i].hSessionHandle);
		if(r)
		{
			printf("SDF_OpenSession fail:%x\n", r);
			goto err;
		}
	}

	gettimeofday(&start_time, NULL);
	for(i=0; i<THREAD_NUM; i++)
	{
		
		pthread_create(&tid[i], NULL, rsa_ext_enc_performance, (void *)&param[i]);
	}

	for(i=0; i<THREAD_NUM; i++)
	{
		pthread_join(tid[i], &tret[i]);
	//	printf("thread %d exit code : %x\n", i, (int)tret[i]);
	}
	gettimeofday(&finish_time, NULL);	
	total_val = (finish_time.tv_sec-start_time.tv_sec)*1000000+finish_time.tv_usec - start_time.tv_usec;
//	fprintf(stdout, "SM2 gen key total time : %f us\n", total_val);
	fprintf(stdout, "RSA%d ext enc performance: %f times/s\n", test_bits, (double)((THREAD_NUM*loop_count)/(total_val/1000000)));	

	gettimeofday(&start_time, NULL);
	for(i=0; i<THREAD_NUM; i++)
	{
		
		pthread_create(&tid[i], NULL, rsa_ext_dec_performance, (void *)&param[i]);
	}

	for(i=0; i<THREAD_NUM; i++)
	{
		pthread_join(tid[i], &tret[i]);
	//	printf("thread %d exit code : %x\n", i, (int)tret[i]);
	}
	gettimeofday(&finish_time, NULL);	
	total_val = (finish_time.tv_sec-start_time.tv_sec)*1000000+finish_time.tv_usec - start_time.tv_usec;
//	fprintf(stdout, "SM2 gen key total time : %f us\n", total_val);
	fprintf(stdout, "RSA%d ext dec performance: %f times/s\n", test_bits, (double)((THREAD_NUM*loop_count)/(total_val/1000000)));

err:
	for(i=0; i<THREAD_NUM; i++)
	{
		if(param[i].hSessionHandle)
			SDF_CloseSession(param[i].hSessionHandle);
		if(param[i].hDevcieHandle)
			SDF_CloseDevice(param[i].hDevcieHandle);	
		free(param[i].data_buf);
		free(param[i].dst_buf);
	}

	return 0;
}



/*
* SM9 PERFORMANCE
*/

void *sm9_gen_master_sign_key_performance(void *arg)
{
	int i;
	u32  r;
	struct thread_param *p_param = (struct thread_param *)arg;
	SM9MasterPrivateKey prikey;
	SM9SignMasterPublicKey pubkey;

//	printf("%s()-thread %d start\n", __func__, (int)(p_param->thread_num));

	for(i=0; i<p_param->loop_count; i++)
	{
		r = SDF_GenerateSignMasterKeyPair_SM9(p_param->hSessionHandle, SGD_SM9_1, &prikey, &pubkey);
		if(r)
		{
			printf("generate sm9 sign master key pair fail:%x\n", r);
			return r;
		}
	}

	pthread_exit((void *)r);
}

u8 privkey_data[32] = {0xa7,0x55,0x7e,0x59,0x2b,0x90,0x36,0x57,0xb2,0x83,0x00,0x31,0x92,0x46,0xa6,0x5a,
				 0xad,0xe5,0x4e,0xaf,0x9b,0x3c,0x13,0xdd,0xe6,0x88,0x32,0xa4,0x62,0x41,0xf3,0x8b};
void *sm9_gen_master_enc_key_performance(void *arg)
{
	int i;
	u32  r;
	struct thread_param *p_param = (struct thread_param *)arg;
	SM9MasterPrivateKey prikey;
	SM9EncMasterPublicKey pubkey;

//	printf("%s()-thread %d start\n", __func__, (int)(p_param->thread_num));
	prikey.bits = SM9ref_MAX_BITS;
	memcpy(prikey.s, &privkey_data[0], 32);
	
	for(i=0; i<p_param->loop_count; i++)
	{
		r = SDF_GenerateEncMasterKeyPair_SM9(p_param->hSessionHandle, SGD_SM9_3, &prikey, &pubkey);
		if(r)
		{
			printf("generate sm9 enc master key pair fail:%x\n", r);
			return r;
		}
	}

	pthread_exit((void *)r);
}


void *sm9_gen_user_sign_key_performance(void *arg)
{
	int i;
	u32  r;
	struct thread_param *p_param = (struct thread_param *)arg;
	SM9MasterPrivateKey prikey;
	SM9UserSignPrivateKey signvk;

//	printf("%s()-thread %d start\n", __func__, (int)(p_param->thread_num));
	prikey.bits = SM9ref_MAX_BITS;
	memcpy(prikey.s, &privkey_data[0], 32);

	for(i=0; i<p_param->loop_count; i++)
	{
		r = EVDF_GenerateUserSignKey_SM9(p_param->hSessionHandle, SGD_SM9_1,&prikey, "Alice", 5, &signvk);
		if(r)
		{
			printf("generate sm9 sign user key pair fail:%x\n", r);
			return r;
		}
	}

	pthread_exit((void *)r);
}


void *sm9_gen_user_enc_key_performance(void *arg)
{
	int i;
	u32  r;
	struct thread_param *p_param = (struct thread_param *)arg;
	SM9MasterPrivateKey prikey;
	SM9UserEncPrivateKey encvk;

//	printf("%s()-thread %d start\n", __func__, (int)(p_param->thread_num));

	for(i=0; i<p_param->loop_count; i++)
	{
		r = EVDF_GenerateUserEncKey_SM9(p_param->hSessionHandle, SGD_SM9_3,&prikey, "Bob", 3, &encvk);
		if(r)
		{
			printf("generate sm9 enc user key pair fail:%x\n", r);
			return r;
		}
	}

	pthread_exit((void *)r);
}


int thread_test_sm9_genkey_performance(int alg_type, int loop_count)
{
	int i,j;
	pthread_t tid[THREAD_NUM];
	void *tret[THREAD_NUM];
	struct thread_param param[THREAD_NUM];
	double total_val = 0;
	u32  r;

	srand((unsigned int)time(NULL));

	for(i=0; i<THREAD_NUM; i++)
	{
		param[i].thread_num = i;
		param[i].alg_type = alg_type;
		param[i].loop_count = loop_count;
		r = SDF_OpenDevice(&param[i].hDevcieHandle);
		if(r)
		{
			printf("SDF_OpenDevice fail:%x\n", r);
			goto err;
		}

		r = SDF_OpenSession(param[i].hDevcieHandle, &param[i].hSessionHandle);
		if(r)
		{
			printf("SDF_OpenSession fail:%x\n", r);
			goto err;
		}
	}

	gettimeofday(&start_time, NULL);
	for(i=0; i<THREAD_NUM; i++)
	{
		
		pthread_create(&tid[i], NULL, sm9_gen_master_sign_key_performance, (void *)&param[i]);
	}

	for(i=0; i<THREAD_NUM; i++)
	{
		pthread_join(tid[i], &tret[i]);
	//	printf("thread %d exit code : %x\n", i, (int)tret[i]);
	}
	gettimeofday(&finish_time, NULL);	
	total_val = (finish_time.tv_sec-start_time.tv_sec)*1000000+finish_time.tv_usec - start_time.tv_usec;
	fprintf(stdout, "SM9 gen master sign key performance: %f times/s\n", (double)((THREAD_NUM*loop_count)/(total_val/1000000)));	


	gettimeofday(&start_time, NULL);
	for(i=0; i<THREAD_NUM; i++)
	{
		
		pthread_create(&tid[i], NULL, sm9_gen_master_enc_key_performance, (void *)&param[i]);
	}

	for(i=0; i<THREAD_NUM; i++)
	{
		pthread_join(tid[i], &tret[i]);
	//	printf("thread %d exit code : %x\n", i, (int)tret[i]);
	}
	gettimeofday(&finish_time, NULL);	
	total_val = (finish_time.tv_sec-start_time.tv_sec)*1000000+finish_time.tv_usec - start_time.tv_usec;
	fprintf(stdout, "SM9 gen master enc key performance: %f times/s\n", (double)((THREAD_NUM*loop_count)/(total_val/1000000)));	


	gettimeofday(&start_time, NULL);
	for(i=0; i<THREAD_NUM; i++)
	{
		
		pthread_create(&tid[i], NULL, sm9_gen_user_sign_key_performance, (void *)&param[i]);
	}

	for(i=0; i<THREAD_NUM; i++)
	{
		pthread_join(tid[i], &tret[i]);
	//	printf("thread %d exit code : %x\n", i, (int)tret[i]);
	}
	gettimeofday(&finish_time, NULL);	
	total_val = (finish_time.tv_sec-start_time.tv_sec)*1000000+finish_time.tv_usec - start_time.tv_usec;
	fprintf(stdout, "SM9 gen user sign key performance: %f times/s\n", (double)((THREAD_NUM*loop_count)/(total_val/1000000)));	

	gettimeofday(&start_time, NULL);
	for(i=0; i<THREAD_NUM; i++)
	{		
		pthread_create(&tid[i], NULL, sm9_gen_user_enc_key_performance, (void *)&param[i]);
	}

	for(i=0; i<THREAD_NUM; i++)
	{
		pthread_join(tid[i], &tret[i]);
	//	printf("thread %d exit code : %x\n", i, (int)tret[i]);
	}
	gettimeofday(&finish_time, NULL);	
	total_val = (finish_time.tv_sec-start_time.tv_sec)*1000000+finish_time.tv_usec - start_time.tv_usec;
	fprintf(stdout, "SM9 gen user enc key performance: %f times/s\n", (double)((THREAD_NUM*loop_count)/(total_val/1000000)));	


err:
	for(i=0; i<THREAD_NUM; i++)
	{
		if(param[i].hSessionHandle)
			SDF_CloseSession(param[i].hSessionHandle);
		if(param[i].hDevcieHandle)
			SDF_CloseDevice(param[i].hDevcieHandle);	
	}

	return 0;
}



void *sm9_ext_sign_performance(void *arg)
{
	int i;
	u32  r;
	struct thread_param *p_param = (struct thread_param *)arg;
	SM9SignMasterPublicKey pubkey;
	SM9UserSignPrivateKey signvk;
	SM9Signature sigval;
	unsigned char data[32];	
	u8 pubkey_data[128] = {
		0x57,0xa0,0xbf,0x4c,0x72,0x9d,0x18,0x2d,0x95,0x35,0x0e,0x59,0x30,0x15,0x16,0xdf,
		0x45,0xf6,0x4b,0xea,0x3c,0x43,0x01,0x88,0xe8,0xab,0xf7,0xfa,0x00,0xe8,0xd8,0x47,
		0x38,0x90,0xaa,0x3e,0xc8,0x49,0x9d,0x17,0xfb,0x31,0x1f,0xe5,0x30,0x47,0xa7,0xf9,
		0x78,0x96,0x79,0x04,0x18,0x33,0x6f,0xfe,0x03,0xd3,0x30,0xa1,0x80,0xf9,0x04,0x0d,
		0xa6,0xfe,0x06,0x55,0xa0,0xb0,0xa8,0x35,0xc2,0x8b,0xc1,0x09,0x28,0x85,0x29,0xdd,
		0xdb,0xf5,0x2f,0x7a,0x36,0xd5,0xb6,0x08,0x6e,0x69,0x57,0x72,0x80,0x4c,0x64,0x58,
		0x89,0xc8,0xa1,0x78,0x6c,0xec,0x66,0x31,0x33,0x2d,0xd3,0xc7,0xef,0xc8,0x9d,0xc6,
		0xfa,0xe3,0xb7,0xb8,0xda,0x9d,0x0b,0xe7,0x45,0x0e,0x4a,0x50,0x8e,0xe5,0xd6,0x78
	};
	u8 user_privkey_data[64] = {
		0x32,0xc1,0x0c,0xa7,0x25,0x3f,0xb0,0xbd,0xf6,0xe5,0xec,0xf5,0x22,0x88,0x3b,0xa1,
		0xcb,0x50,0x20,0x2b,0xe0,0x7b,0x46,0x13,0xc8,0x72,0xb5,0xf6,0xc3,0x8a,0xda,0x69,
		0xac,0x27,0x44,0xe0,0xbd,0x87,0xbe,0xa4,0x2f,0xd8,0x52,0x22,0xf8,0x12,0x61,0x9a,
		0x1a,0xce,0xa5,0x07,0xe3,0x9e,0xe3,0x2e,0x55,0x8c,0xe2,0x40,0xb5,0x77,0xc1,0xc7
	};

//	printf("%s()-thread %d start\n", __func__, (int)(p_param->thread_num));

	memcpy(pubkey.xa, &pubkey_data[0], 32);
	memcpy(pubkey.xb, &pubkey_data[32], 32);
	memcpy(pubkey.ya, &pubkey_data[64], 32);
	memcpy(pubkey.yb, &pubkey_data[96], 32);
	memcpy(signvk.x, &user_privkey_data[0], 32);
	memcpy(signvk.y, &user_privkey_data[32], 32);

	for(i=0; i<32; i++)
		data[i] = (u8)(i+0x80);

	for(i=0; i<p_param->loop_count; i++)
	{
		r = EVDF_SignWithMasterEPK_SM9(p_param->hSessionHandle, &pubkey, &signvk, data, 32, &sigval);
		if(r)
		{
			printf("external sm9 sign fail:%x\n", r);
			return r;
		}
	}

	pthread_exit((void *)r);
}


void *sm9_ext_verify_performance(void *arg)
{
	int i;
	u32  r;
	struct thread_param *p_param = (struct thread_param *)arg;
	SM9MasterPrivateKey prikey;
	SM9SignMasterPublicKey pubkey;
	SM9UserSignPrivateKey signvk; 
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

//	printf("%s()-thread %d start\n", __func__, (int)(p_param->thread_num));

	memcpy(pubkey.xa, &pubkey_data[0], 32);
	memcpy(pubkey.xb, &pubkey_data[32], 32);
	memcpy(pubkey.ya, &pubkey_data[64], 32);
	memcpy(pubkey.yb, &pubkey_data[96], 32);
	
	memcpy(sigval.h, sig_h_data, 32);
	memcpy(sigval.x, &sig_s_data[0], 32);
	memcpy(sigval.y, &sig_s_data[32], 32);

	for(i=0; i<p_param->loop_count; i++)
	{
		r = SDF_VerifyWithMasterEPK_SM9(p_param->hSessionHandle, &pubkey, user_id_data, 5, sig_plain_data, 8, &sigval);
		if(r)
		{
			printf("external sm9 verify fail:%x\n", r);
			return r;
		}
	}

	pthread_exit((void *)r);
}


int thread_test_sm9_ext_sign_verify_performance(int alg_type, int loop_count)
{
	int i,j;
	pthread_t tid[THREAD_NUM];
	void *tret[THREAD_NUM];
	struct thread_param param[THREAD_NUM];
	double total_val = 0;
	u32  r;

	srand((unsigned int)time(NULL));

	for(i=0; i<THREAD_NUM; i++)
	{
		param[i].thread_num = i;
		param[i].alg_type = alg_type;
		param[i].loop_count = loop_count;
		r = SDF_OpenDevice(&param[i].hDevcieHandle);
		if(r)
		{
			printf("SDF_OpenDevice fail:%x\n", r);
			goto err;
		}

		r = SDF_OpenSession(param[i].hDevcieHandle, &param[i].hSessionHandle);
		if(r)
		{
			printf("SDF_OpenSession fail:%x\n", r);
			goto err;
		}
	}

	gettimeofday(&start_time, NULL);
	for(i=0; i<THREAD_NUM; i++)
	{
		
		pthread_create(&tid[i], NULL, sm9_ext_sign_performance, (void *)&param[i]);
	}

	for(i=0; i<THREAD_NUM; i++)
	{
		pthread_join(tid[i], &tret[i]);
	//	printf("thread %d exit code : %x\n", i, (int)tret[i]);
	}
	gettimeofday(&finish_time, NULL);	
	total_val = (finish_time.tv_sec-start_time.tv_sec)*1000000+finish_time.tv_usec - start_time.tv_usec;
	fprintf(stdout, "SM9 ext sign performance: %f times/s\n", (double)((THREAD_NUM*loop_count)/(total_val/1000000)));	

	gettimeofday(&start_time, NULL);
	for(i=0; i<THREAD_NUM; i++)
	{
		
		pthread_create(&tid[i], NULL, sm9_ext_verify_performance, (void *)&param[i]);
	}

	for(i=0; i<THREAD_NUM; i++)
	{
		pthread_join(tid[i], &tret[i]);
	//	printf("thread %d exit code : %x\n", i, (int)tret[i]);
	}
	gettimeofday(&finish_time, NULL);	
	total_val = (finish_time.tv_sec-start_time.tv_sec)*1000000+finish_time.tv_usec - start_time.tv_usec;
	fprintf(stdout, "SM9 ext verify performance: %f times/s\n", (double)((THREAD_NUM*loop_count)/(total_val/1000000)));

err:
	for(i=0; i<THREAD_NUM; i++)
	{
		if(param[i].hSessionHandle)
			SDF_CloseSession(param[i].hSessionHandle);
		if(param[i].hDevcieHandle)
			SDF_CloseDevice(param[i].hDevcieHandle);	
	}

	return 0;
}


void *sm9_ext_enc_performance(void *arg)
{
	int i;
	u32  r;
	struct thread_param *p_param = (struct thread_param *)arg;
	SM9EncMasterPublicKey pubkey;
	SM9Cipher *psm9cipher = (SM9Cipher *)p_param->dst_buf;
	u8 pubkey_data[] = {
		0xab,0xf3,0x67,0x19,0x3e,0xab,0xb7,0x05,0xc0,0xc3,0x8c,0xc7,0x23,0xf6,0x5c,0x58,
		0x05,0x4e,0x72,0x5a,0x8a,0xbb,0xbf,0xbc,0x46,0x43,0xfb,0x1f,0xae,0x15,0x54,0x13,
		0x3a,0xf7,0x1b,0xbf,0x52,0xdd,0x74,0xee,0x4f,0xdf,0x2e,0xce,0x82,0x22,0x48,0x2a,
		0x9e,0x9f,0x1b,0xc6,0xf3,0xd9,0x94,0xfa,0x69,0x3f,0x42,0x4d,0x6f,0x6b,0x3d,0xcb
	};
	
	u8 user_id_data[] = {0xa6,0x04,0x9b,0x4e,0x66};

//	printf("%s()-thread %d start\n", __func__, (int)(p_param->thread_num));

	memcpy(pubkey.x, &pubkey_data[0], 32);
	memcpy(pubkey.y, &pubkey_data[32], 32);

	for(i=0; i<p_param->loop_count; i++)
	{
		//r = SDF_ExternalEncrypt_ECC(p_param->hSessionHandle, p_param->alg_type, &eccpubkey, p_param->data_buf, p_param->data_len, pecccipher);
		r = SDF_EncryptWithMasterEPK_SM9(p_param->hSessionHandle, &pubkey, user_id_data, 5, p_param->alg_type, NULL, p_param->data_buf, p_param->data_len, psm9cipher);
		if(r)
		{
			printf("external sm9 encrypt fail:%x\n", r);
			return r;
		}
	}

	pthread_exit((void *)r);
}


void *sm9_ext_dec_performance(void *arg)
{
	int i;
	u32  r;
	struct thread_param *p_param = (struct thread_param *)arg;
	int declen;
	SM9MasterPrivateKey prikey;
	SM9EncMasterPublicKey pubkey;
	SM9UserEncPrivateKey encvk;	
	SM9Cipher *psm9cipher = (SM9Cipher *)p_param->dst_buf;
	
	u8 prikey_data[128] = {
		0x7a,0x73,0x80,0x8d,0xc0,0x6e,0x16,0xae,0x8f,0xbd,0x4d,0x11,0x37,0x5a,0xf8,0x19,
		0x4c,0x5d,0x20,0x03,0x60,0x93,0x48,0x1d,0x77,0x73,0xf1,0x1a,0x4d,0xef,0x64,0x45,
		0xa3,0x10,0xed,0xac,0xaf,0xb0,0xd8,0x1f,0x01,0xa3,0x79,0x2b,0xab,0xaa,0xba,0x8e,
		0x94,0xe5,0xf9,0xaf,0x96,0xa2,0xe8,0x03,0x14,0x10,0x4a,0x41,0xaf,0x4d,0x68,0x56,
		0xae,0xa7,0x73,0x3c,0x52,0xd9,0x45,0xfa,0xed,0x92,0x5a,0xc9,0x08,0xbb,0x5b,0xae,
		0x81,0x3a,0xb0,0x8a,0x5d,0x83,0xb6,0xf2,0xd4,0x1a,0xea,0x07,0x9b,0x33,0x15,0xcc,
		0x61,0x6c,0xad,0xcf,0xf2,0xc9,0x0a,0x26,0xca,0x56,0x45,0x01,0x45,0x66,0x59,0xb0,
		0x39,0x15,0x16,0x00,0x96,0x39,0xe0,0x1c,0x60,0x6f,0x52,0xd7,0xff,0x61,0x61,0xfa
	};
	u8 user_id_data[5] = {0xa6,0x04,0x9b,0x4e,0x66};
//	printf("%s()-thread %d start\n", __func__, (int)(p_param->thread_num));

	memcpy(encvk.xa, &prikey_data[0], 32);
	memcpy(encvk.xb, &prikey_data[32], 32);
	memcpy(encvk.ya, &prikey_data[64], 32);
	memcpy(encvk.yb, &prikey_data[96], 32);
	
	for(i=0; i<p_param->loop_count; i++)
	{
		declen = 256;
		//r = SDF_ExternalDecrypt_ECC(p_param->hSessionHandle, p_param->alg_type, &eccprikey, pecccipher, p_param->dst_buf, &declen);
		r = EVDF_DecryptWithUserEncKey_SM9(p_param->hSessionHandle, &encvk, user_id_data, 5, NULL, psm9cipher, p_param->data_buf, &declen);
		if(r)
		{
			printf("external sm9 decrypt fail:%x\n", r);
			return r;			
		}
	}

	pthread_exit((void *)r);
}


int thread_test_sm9_ext_enc_dec_performance(int alg_type, int loop_count, int test_len)
{
	int i,j;
	pthread_t tid[THREAD_NUM];
	void *tret[THREAD_NUM];
	struct thread_param param[THREAD_NUM];
	double total_val = 0;
	u32  r;

	srand((unsigned int)time(NULL));

	for(i=0; i<THREAD_NUM; i++)
	{
		param[i].thread_num = i;
		param[i].alg_type = alg_type;
		param[i].loop_count = loop_count;
		param[i].data_len = test_len;
		param[i].data_buf = malloc(test_len);
		param[i].dst_buf = malloc(test_len+0x200);
		for(j=0; j<test_len; j++)
		{
			param[i].data_buf[j] = (unsigned char)rand();
		}
		r = SDF_OpenDevice(&param[i].hDevcieHandle);
		if(r)
		{
			printf("SDF_OpenDevice fail:%x\n", r);
			goto err;
		}

		r = SDF_OpenSession(param[i].hDevcieHandle, &param[i].hSessionHandle);
		if(r)
		{
			printf("SDF_OpenSession fail:%x\n", r);
			goto err;
		}
	}

	gettimeofday(&start_time, NULL);
	for(i=0; i<THREAD_NUM; i++)
	{
		
		pthread_create(&tid[i], NULL, sm9_ext_enc_performance, (void *)&param[i]);
	}

	for(i=0; i<THREAD_NUM; i++)
	{
		pthread_join(tid[i], &tret[i]);
	//	printf("thread %d exit code : %x\n", i, (int)tret[i]);
	}
	gettimeofday(&finish_time, NULL);	
	total_val = (finish_time.tv_sec-start_time.tv_sec)*1000000+finish_time.tv_usec - start_time.tv_usec;
	fprintf(stdout, "SM9 %s mode ext enc performance: %f times/s\n", _get_sym_type_name(alg_type), (double)((THREAD_NUM*loop_count)/(total_val/1000000)));	

	gettimeofday(&start_time, NULL);
	for(i=0; i<THREAD_NUM; i++)
	{
		
		pthread_create(&tid[i], NULL, sm9_ext_dec_performance, (void *)&param[i]);
	}

	for(i=0; i<THREAD_NUM; i++)
	{
		pthread_join(tid[i], &tret[i]);
	//	printf("thread %d exit code : %x\n", i, (int)tret[i]);
	}
	gettimeofday(&finish_time, NULL);	
	total_val = (finish_time.tv_sec-start_time.tv_sec)*1000000+finish_time.tv_usec - start_time.tv_usec;
	fprintf(stdout, "SM9 %s mode ext dec performance: %f times/s\n", _get_sym_type_name(alg_type), (double)((THREAD_NUM*loop_count)/(total_val/1000000)));

err:
	for(i=0; i<THREAD_NUM; i++)
	{
		if(param[i].hSessionHandle)
			SDF_CloseSession(param[i].hSessionHandle);
		if(param[i].hDevcieHandle)
			SDF_CloseDevice(param[i].hDevcieHandle);	
		free(param[i].data_buf);
		free(param[i].dst_buf);
	}

	return 0;
}



int multi_performance_test(void)
{
#if 1
	thread_test_symm_performance(SGD_SM1_ECB, SYMM_LEN);
	thread_test_symm_performance(SGD_SM1_CBC, SYMM_LEN);
	thread_test_symm_performance(SGD_SM1_CFB, SYMM_LEN);
	thread_test_symm_performance(SGD_SM1_OFB, SYMM_LEN);
	thread_test_symm_performance(SGD_SMS4_ECB, SYMM_LEN);
	thread_test_symm_performance(SGD_SMS4_CBC, SYMM_LEN);
	thread_test_symm_performance(SGD_SMS4_CFB, SYMM_LEN);
	thread_test_symm_performance(SGD_SMS4_OFB, SYMM_LEN);	
	thread_test_symm_performance(SGD_SSF33_ECB, SYMM_LEN);
	thread_test_symm_performance(SGD_SSF33_CBC, SYMM_LEN);
	thread_test_symm_performance(SGD_SSF33_CFB, SYMM_LEN);
	thread_test_symm_performance(SGD_SSF33_OFB, SYMM_LEN);
	thread_test_symm_performance(SGD_SM6_ECB, SYMM_LEN);
	thread_test_symm_performance(SGD_SM6_CBC, SYMM_LEN);
	thread_test_symm_performance(SGD_SM6_CFB, SYMM_LEN);
	thread_test_symm_performance(SGD_SM6_OFB, SYMM_LEN);	
	thread_test_symm_performance(SGD_AES_ECB, SYMM_LEN);
	thread_test_symm_performance(SGD_AES_CBC, SYMM_LEN);
	thread_test_symm_performance(SGD_AES_CFB, SYMM_LEN);
	thread_test_symm_performance(SGD_AES_OFB, SYMM_LEN);		
	thread_test_hash_performance(SGD_SM3, HASH_LEN);
	thread_test_hash_performance(SGD_SHA1, HASH_LEN);
	thread_test_hash_performance(SGD_SHA256, HASH_LEN);
	thread_test_hash_performance(SGD_SHA512, HASH_LEN);
	thread_test_hash_performance(SGD_SHA0, HASH_LEN);
	thread_test_hash_performance(SGD_SHA224, HASH_LEN);
	thread_test_hash_performance(SGD_SHA384, HASH_LEN);
#else		
	multi_thread_test_symm_performance(SGD_SM1_ECB, SYMM_PACKET_LEN);		
	multi_thread_test_symm_performance(SGD_SM1_CBC, SYMM_PACKET_LEN);		
	multi_thread_test_symm_performance(SGD_SM1_CFB, SYMM_PACKET_LEN);		
	multi_thread_test_symm_performance(SGD_SM1_OFB, SYMM_PACKET_LEN);		
	multi_thread_test_symm_performance(SGD_SMS4_ECB, SYMM_PACKET_LEN);		
	multi_thread_test_symm_performance(SGD_SMS4_CBC, SYMM_PACKET_LEN);		
	multi_thread_test_symm_performance(SGD_SMS4_CFB, SYMM_PACKET_LEN);		
	multi_thread_test_symm_performance(SGD_SMS4_OFB, SYMM_PACKET_LEN);			
	multi_thread_test_symm_performance(SGD_SSF33_ECB, SYMM_PACKET_LEN);		
	multi_thread_test_symm_performance(SGD_SSF33_CBC, SYMM_PACKET_LEN);		
	multi_thread_test_symm_performance(SGD_SSF33_CFB, SYMM_PACKET_LEN);		
	multi_thread_test_symm_performance(SGD_SSF33_OFB, SYMM_PACKET_LEN);		
	multi_thread_test_symm_performance(SGD_SM6_ECB, SYMM_PACKET_LEN);		
	multi_thread_test_symm_performance(SGD_SM6_CBC, SYMM_PACKET_LEN);		
	multi_thread_test_symm_performance(SGD_SM6_CFB, SYMM_PACKET_LEN);		
	multi_thread_test_symm_performance(SGD_SM6_OFB, SYMM_PACKET_LEN);			
	multi_thread_test_symm_performance(SGD_AES_ECB, SYMM_PACKET_LEN);		
	multi_thread_test_symm_performance(SGD_AES_CBC, SYMM_PACKET_LEN);		
	multi_thread_test_symm_performance(SGD_AES_CFB, SYMM_PACKET_LEN);		
	multi_thread_test_symm_performance(SGD_AES_OFB, SYMM_PACKET_LEN);		
	multi_thread_test_hash_performance(SGD_SM3, HASH_PACKET_LEN);		
	multi_thread_test_hash_performance(SGD_SHA1, HASH_PACKET_LEN);		
	multi_thread_test_hash_performance(SGD_SHA256, HASH_PACKET_LEN);		
	multi_thread_test_hash_performance(SGD_SHA512, HASH_PACKET_LEN);		
	multi_thread_test_hash_performance(SGD_SHA0, HASH_PACKET_LEN);		
	multi_thread_test_hash_performance(SGD_SHA224, HASH_PACKET_LEN);		
	multi_thread_test_hash_performance(SGD_SHA384, HASH_PACKET_LEN);		
#endif	
	thread_test_sm2_genkey_performance(SGD_SM2_1, SM2_LOOP_COUNT);
	thread_test_sm2_ext_sign_verify_performance(SGD_SM2_1, SM2_LOOP_COUNT);
	thread_test_sm2_ext_enc_dec_performance(SGD_SM2_3, SM2_LOOP_COUNT, 32);
	thread_test_sm2_int_sign_verify_performance(SGD_SM2_1, SM2_LOOP_COUNT);
	thread_test_sm2_int_enc_dec_performance(SGD_SM2_3, SM2_LOOP_COUNT, 32);
	thread_test_rsa_genkey_performance(SGD_RSA, RSA_LOOP_COUNT, 1024);
	thread_test_rsa_genkey_performance(SGD_RSA, RSA_LOOP_COUNT, 2048);
	thread_test_rsa_ext_enc_dec_performance(SGD_RSA, RSA_LOOP_COUNT*100, 1024);
	thread_test_rsa_ext_enc_dec_performance(SGD_RSA, RSA_LOOP_COUNT*100, 2048);
	return 0;
}
