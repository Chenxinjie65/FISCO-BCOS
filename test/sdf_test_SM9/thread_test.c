#include <sdf.h>
#include <sdf_type.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <malloc.h>
#include <pthread.h>
#include <semaphore.h>

#define THREAD_NUM	4

extern u32 Symm_Test(void *hSessionHandle);

struct thread_param{
	int thread_num;
	void *hDevcieHandle;
	void *hSessionHandle;
};
struct timeval start_time, finish_time;

void *symm_func(void *arg)
{
	u32  r;
	void *hDevcieHandle = NULL;
	void *hSessionHandle = NULL;
	struct thread_param *p_param = (struct thread_param *)arg;

	printf("%s()-thread %d start\n", __func__, (int)(p_param->thread_num));

	r = SDF_OpenDevice(&hDevcieHandle);
	if(r)
	{
		printf("SDF_OpenDevice fail:%x\n", r);
		pthread_exit((void *)r);
	}

	r = SDF_OpenSession(hDevcieHandle, &hSessionHandle);
	if(r)
	{
		printf("SDF_OpenSession fail:%x\n", r);
		goto err;
	}

	r = Symm_Test(hSessionHandle);
	if(r)
	{
		printf("Symm_Test fail:%x\n", r);
		goto err;
	}

err:
	if(hSessionHandle)
		SDF_CloseSession(hSessionHandle);
	if(hDevcieHandle)
		SDF_CloseDevice(hDevcieHandle);	

	pthread_exit((void *)r);
}

int thread_test_symm(void)
{
	int i;
	pthread_t tid[THREAD_NUM];
	void *tret[THREAD_NUM];
	struct thread_param param[THREAD_NUM];
	double total_val = 0;

	gettimeofday(&start_time, NULL);
	for(i=0; i<THREAD_NUM; i++)
	{
		param[i].thread_num = i;
		pthread_create(&tid[i], NULL, symm_func, (void *)&param[i]);
	}

	for(i=0; i<THREAD_NUM; i++)
	{
		pthread_join(tid[i], &tret[i]);
		printf("thread %d exit code : %x\n", i, (int)tret[i]);
	}
	gettimeofday(&finish_time, NULL);	
	total_val = (finish_time.tv_sec-start_time.tv_sec);//*1000000+finish_time.tv_usec - start_time.tv_usec;
	fprintf(stdout, "SM1 ecb enc total time : %f s\n", total_val);

	return 0;
}


















#define ALG_THREAD_NUM	9
#define ALO_LOOP_COUNT	5000//100
pthread_t g_tid[ALG_THREAD_NUM] = {0};
void *g_tret[ALG_THREAD_NUM];

void cancel_all_tread(void)
{
	int i;
	
	for(i=0; i<ALG_THREAD_NUM; i++)
	{
		if(g_tid[i])
			pthread_cancel(g_tid[i]);
	}

	return;
}


void *asymm_valid_loop_test(void *arg)
{
	int i;
	u32  r;
	struct thread_param *p_param = (struct thread_param *)arg;

	printf("%s()-thread %d start\n", __func__, (int)(p_param->thread_num));

	for(i=0; i<ALO_LOOP_COUNT*100; i++)
	{
		if(i%100 == 0)
			printf("%s()-thread[%d] count : %d \n", __func__, (int)(p_param->thread_num), i);
			
		r = Asymm_Validity_Test(p_param->hSessionHandle);
		if(r)
		{
			printf("Asymm_Validity_Test fail:%x\n", r);
			cancel_all_tread();
			goto err;		
		}

		r = ECC_ExternalKey_Test1(p_param->hSessionHandle);
		if(r)
		{
			printf("ECC_ExternalKey_Test1 fail:%x\n", r);
			cancel_all_tread();
			goto err;		
		}

		r = ECC_ExternalKey_Test2(p_param->hSessionHandle);
		if(r)
		{
			printf("ECC_ExternalKey_Test2 fail:%x\n", r);
			cancel_all_tread();
			goto err;		
		}
	}

err:
	printf("%s()-thread %d exit\n", __func__, (int)(p_param->thread_num));
	pthread_exit((void *)r);
}

void *symm_valid_loop_test(void *arg)
{
	int i;
	u32  r;
	struct thread_param *p_param = (struct thread_param *)arg;

	printf("%s()-thread %d start\n", __func__, (int)(p_param->thread_num));

	for(i=0; i<ALO_LOOP_COUNT*80; i++)
	{
		if(i%80 == 0)
			printf("%s()-thread[%d] count : %d \n", __func__, (int)(p_param->thread_num), i);
			
		r = Symm_Validity_Test(p_param->hSessionHandle);
		if(r)
		{
			printf("Symm_Validity_Test fail:%x\n", r);
			cancel_all_tread();
			goto err;		
		}
	}

err:
	printf("%s()-thread %d exit\n", __func__, (int)(p_param->thread_num));
	pthread_exit((void *)r);
}

void *rsa_valid_loop_test(void *arg)
{
	int i;
	u32  r;
	struct thread_param *p_param = (struct thread_param *)arg;

	printf("%s()-thread %d start\n", __func__, (int)(p_param->thread_num));

	for(i=0; i<ALO_LOOP_COUNT*100; i++)
	{
		if(i%100 == 0)
			printf("%s()-thread[%d] count : %d \n", __func__, (int)(p_param->thread_num), i);
			
		r = RSA_Validity_Test(p_param->hSessionHandle);
		if(r)
		{
			printf("RSA_Validity_Test fail:%x\n", r);
			cancel_all_tread();
			goto err;		
		}
	}

err:
	printf("%s()-thread %d exit\n", __func__, (int)(p_param->thread_num));
	pthread_exit((void *)r);
}

void *hash_z_valid_loop_test(void *arg)
{
	int i;
	u32  r;
	struct thread_param *p_param = (struct thread_param *)arg;

	printf("%s()-thread %d start\n", __func__, (int)(p_param->thread_num));

	for(i=0; i<ALO_LOOP_COUNT*100; i++)
	{
		if(i%100 == 0)
			printf("%s()-thread[%d] count : %d \n", __func__, (int)(p_param->thread_num), i);
			
		r = Hash_Z_Test3(p_param->hSessionHandle);
		if(r)
		{
			printf("Hash_Z_Test3 fail:%x\n", r);
			cancel_all_tread();
			goto err;		
		}
	}

err:
	printf("%s()-thread %d exit\n", __func__, (int)(p_param->thread_num));
	pthread_exit((void *)r);
}

void *symm_rand_loop_test(void *arg)
{
	int i;
	u32  r;
	struct thread_param *p_param = (struct thread_param *)arg;

	printf("%s()-thread %d start\n", __func__, (int)(p_param->thread_num));

	for(i=0; i<ALO_LOOP_COUNT; i++)
	{
		printf("%s()-thread[%d] count : %d \n", __func__, (int)(p_param->thread_num), i);
		
		r = Symm_Test(p_param->hSessionHandle);
		if(r)
		{
			printf("Symm_Test fail:%x\n", r);
			cancel_all_tread();
			goto err;		
		}
	}

err:
	printf("%s()-thread %d exit\n", __func__, (int)(p_param->thread_num));
	pthread_exit((void *)r);
}

void *hash_rand_loop_test(void *arg)
{
	int i;
	u32  r;
	struct thread_param *p_param = (struct thread_param *)arg;

	printf("%s()-thread %d start\n", __func__, (int)(p_param->thread_num));

	for(i=0; i<ALO_LOOP_COUNT; i++)
	{
		printf("%s()-thread[%d] count : %d \n", __func__, (int)(p_param->thread_num), i);
		
		r = HASH_Test(p_param->hSessionHandle);
		if(r)
		{
			printf("HASH_Test fail:%x\n", r);
			cancel_all_tread();
			goto err;		
		}
	}

err:
	printf("%s()-thread %d exit\n", __func__, (int)(p_param->thread_num));
	pthread_exit((void *)r);
}

void *genkey_loop_test(void *arg)
{
	int i;
	u32  r;
	struct thread_param *p_param = (struct thread_param *)arg;

	printf("%s()-thread %d start\n", __func__, (int)(p_param->thread_num));

	for(i=0; i<ALO_LOOP_COUNT; i++)
	{
		printf("%s()-thread[%d] count : %d \n", __func__, (int)(p_param->thread_num), i);
		
		r = ECC_Test(p_param->hSessionHandle);
		if(r)
		{
			printf("ECC_Test fail:%x\n", r);
			cancel_all_tread();
			goto err;		
		}

		r = RSA_Test(p_param->hSessionHandle);
		if(r)
		{
			printf("RSA_Test fail:%x\n", r);
			cancel_all_tread();
			goto err;		
		}

		r = RSA1024_Test1(p_param->hSessionHandle);
		if(r)
		{
			printf("RSA_Test1 fail:%x\n", r);
			cancel_all_tread();
			goto err;		
		}
	}

err:
	printf("%s()-thread %d exit\n", __func__, (int)(p_param->thread_num));
	pthread_exit((void *)r);
}


void *internal_rsakey_loop_test(void *arg)
{
	int i;
	u32  r;
	struct thread_param *p_param = (struct thread_param *)arg;

	printf("%s()-thread %d start\n", __func__, (int)(p_param->thread_num));

	r = GetAccessRight(p_param->hSessionHandle);
	if(r)
	{
		printf("GetAccessRight fail:%x\n", r);
		cancel_all_tread();
		goto err;
	}

	for(i=0; i<ALO_LOOP_COUNT*30; i++)
	{
		if(i%30 == 0)
			printf("%s()-thread[%d] count : %d \n", __func__, (int)(p_param->thread_num), i);
			
		r = RSA_Calc_Test(p_param->hSessionHandle);
		if(r)
		{
			printf("RSA_Calc_Test fail:%x\n", r);
			cancel_all_tread();
			goto err;		
		}

		r = RSA_DigitEnvelope_Test(p_param->hSessionHandle);
		if(r)
		{
			printf("RSA_DigitEnvelope_Test fail:%x\n", r);
			cancel_all_tread();
			goto err;		
		}


		r = RSA_SessionKey_Test1(p_param->hSessionHandle);
		if(r)
		{
			printf("RSA_SessionKey_Test1 fail:%x\n", r);
			cancel_all_tread();
			goto err;		
		}


		r = RSA_SessionKey_Test2(p_param->hSessionHandle);
		if(r)
		{
			printf("RSA_SessionKey_Test2 fail:%x\n", r);
			cancel_all_tread();
			goto err;		
		}

		r = RSA1024_Test2(p_param->hSessionHandle);
		if(r)
		{
			printf("RSA_Test2 fail:%x\n", r);
			cancel_all_tread();
			goto err;
		}

		r = RSA1024_InternalKey_Test(p_param->hSessionHandle);
		if(r)
		{
			printf("RSA1024_InternalKey_Test fail:%x\n", r);
			cancel_all_tread();
			goto err;
		}

		r = RSA1024_SessionKey_Test1(p_param->hSessionHandle);
		if(r)
		{
			printf("RSA1024_SessionKey_Test1 fail:%x\n", r);
			cancel_all_tread();
			goto err;
		}


		r = RSA1024_SessionKey_Test2(p_param->hSessionHandle);
		if(r)
		{
			printf("RSA1024_SessionKey_Test2 fail:%x\n", r);
			cancel_all_tread();
			goto err;
		}


		r = RSA1024_DigitEnvelope_Test(p_param->hSessionHandle);
		if(r)
		{
			printf("RSA1024_DigitEnvelope_Test fail:%x\n", r);
			cancel_all_tread();
			goto err;
		}
	}

err:
	printf("%s()-thread %d exit\n", __func__, (int)(p_param->thread_num));
	pthread_exit((void *)r);
}


void *internal_ecckey_loop_test(void *arg)
{
	int i;
	u32  r;
	struct thread_param *p_param = (struct thread_param *)arg;

	printf("%s()-thread %d start\n", __func__, (int)(p_param->thread_num));

	r = GetAccessRight(p_param->hSessionHandle);
	if(r)
	{
		printf("GetAccessRight fail:%x\n", r);
		cancel_all_tread();
		goto err;
	}

	for(i=0; i<ALO_LOOP_COUNT*30; i++)
	{
		if(i%30 == 0)
			printf("%s()-thread[%d] count : %d \n", __func__, (int)(p_param->thread_num), i);
			
		r = ECC_Calc_Test(p_param->hSessionHandle);
		if(r)
		{
			printf("ECC_Calc_Test fail:%x\n", r);
			cancel_all_tread();
			goto err;		
		}

		r = ECC_DigitEnvelope_Test(p_param->hSessionHandle);
		if(r)
		{
			printf("ECC_DigitEnvelope_Test fail:%x\n", r);
			cancel_all_tread();
			goto err;		
		}

		r = ECC_ExchangeKey_Test(p_param->hSessionHandle);
		if(r)
		{
			printf("ECC_ExchangeKey_Test fail:%x\n", r);
			cancel_all_tread();
			goto err;		
		}

		r = ECC_InternalKey_Test1(p_param->hSessionHandle);
		if(r)
		{
			printf("ECC_InternalKey_Test1 fail:%x\n", r);
			cancel_all_tread();
			goto err;				
		}

		r = ECC_InternalKey_Test2(p_param->hSessionHandle);
		if(r)
		{
			printf("ECC_InternalKey_Test2 fail:%x\n", r);
			cancel_all_tread();
			goto err;				
		}

		r = ECC_SessionKey_Test1(p_param->hSessionHandle);
		if(r)
		{
			printf("ECC_SessionKey_Test1 fail:%x\n", r);
			cancel_all_tread();
			goto err;		
		}

		r = ECC_SessionKey_Test2(p_param->hSessionHandle);
		if(r)
		{
			printf("ECC_SessionKey_Test2 fail:%x\n", r);
			cancel_all_tread();
			goto err;		
		}
	}

err:
	printf("%s()-thread %d exit\n", __func__, (int)(p_param->thread_num));
	pthread_exit((void *)r);
}


int thread_test_all_alg(void)
{	
	struct thread_param param[ALG_THREAD_NUM];
	int i,j;
	u32  r;

	for(i=0; i<ALG_THREAD_NUM; i++)
	{
		param[i].thread_num = i;
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

	pthread_create(&g_tid[0], NULL, asymm_valid_loop_test, (void *)&param[0]);
	pthread_create(&g_tid[1], NULL, symm_valid_loop_test, (void *)&param[1]);
	pthread_create(&g_tid[2], NULL, rsa_valid_loop_test, (void *)&param[2]);
	pthread_create(&g_tid[3], NULL, hash_z_valid_loop_test, (void *)&param[3]);
	pthread_create(&g_tid[4], NULL, symm_rand_loop_test, (void *)&param[4]);
	pthread_create(&g_tid[5], NULL, hash_rand_loop_test, (void *)&param[5]);
	pthread_create(&g_tid[6], NULL, internal_rsakey_loop_test, (void *)&param[6]);
	pthread_create(&g_tid[7], NULL, internal_ecckey_loop_test, (void *)&param[7]);
	pthread_create(&g_tid[8], NULL, genkey_loop_test, (void *)&param[8]);
	

	pthread_join(g_tid[0], &g_tret[0]);
	pthread_join(g_tid[1], &g_tret[1]);
	pthread_join(g_tid[2], &g_tret[2]);
	pthread_join(g_tid[3], &g_tret[3]);
	pthread_join(g_tid[4], &g_tret[4]);
	pthread_join(g_tid[5], &g_tret[5]);
	pthread_join(g_tid[6], &g_tret[6]);
	pthread_join(g_tid[7], &g_tret[7]);
	pthread_join(g_tid[8], &g_tret[8]);

err:
	for(i=0; i<ALG_THREAD_NUM; i++)
	{
		printf("thread%d return value : 0x%x\n", i, (int)g_tret[i]);
		if(param[i].hSessionHandle)
			SDF_CloseSession(param[i].hSessionHandle);
		if(param[i].hDevcieHandle)
			SDF_CloseDevice(param[i].hDevcieHandle);	
	}

	return 0;
}


int thread_test_single_dev(void)
{	
	struct thread_param param[ALG_THREAD_NUM];
	int i,j;
	u32  r;

	r = SDF_OpenDevice(&param[0].hDevcieHandle);
	if(r)
	{
		printf("SDF_OpenDevice fail:%x\n", r);
		goto err;
	}

	for(i=0; i<ALG_THREAD_NUM; i++)
	{
		param[i].thread_num = i;
		r = SDF_OpenSession(param[0].hDevcieHandle, &param[i].hSessionHandle);
		if(r)
		{
			printf("SDF_OpenSession fail:%x\n", r);
			goto err;
		}
	}


	pthread_create(&g_tid[0], NULL, asymm_valid_loop_test, (void *)&param[0]);
	pthread_create(&g_tid[1], NULL, symm_valid_loop_test, (void *)&param[1]);
	pthread_create(&g_tid[2], NULL, rsa_valid_loop_test, (void *)&param[2]);
	pthread_create(&g_tid[3], NULL, hash_z_valid_loop_test, (void *)&param[3]);
	pthread_create(&g_tid[4], NULL, symm_rand_loop_test, (void *)&param[4]);
	pthread_create(&g_tid[5], NULL, hash_rand_loop_test, (void *)&param[5]);
	pthread_create(&g_tid[6], NULL, internal_rsakey_loop_test, (void *)&param[6]);
	pthread_create(&g_tid[7], NULL, internal_ecckey_loop_test, (void *)&param[7]);
	pthread_create(&g_tid[8], NULL, genkey_loop_test, (void *)&param[8]);

	pthread_join(g_tid[0], &g_tret[0]);
	pthread_join(g_tid[1], &g_tret[1]);
	pthread_join(g_tid[2], &g_tret[2]);
	pthread_join(g_tid[3], &g_tret[3]);
	pthread_join(g_tid[4], &g_tret[4]);
	pthread_join(g_tid[5], &g_tret[5]);
	pthread_join(g_tid[6], &g_tret[6]);
	pthread_join(g_tid[7], &g_tret[7]);
	pthread_join(g_tid[8], &g_tret[8]);

err:
	for(i=0; i<ALG_THREAD_NUM; i++)
	{
		printf("thread%d return value : 0x%x\n", i, (int)g_tret[i]);	
		if(param[i].hSessionHandle)
			SDF_CloseSession(param[i].hSessionHandle);
	}
	if(param[0].hDevcieHandle)
		SDF_CloseDevice(param[0].hDevcieHandle);

	return 0;
}


