#define SM1_ECB_PER_TEST       1
#define SM1_CBC_PER_TEST       1 
#define SMS4_ECB_PER_TEST      1
#define SMS4_CBC_PER_TEST      1
#define SSF33_ECB_PER_TEST     1
#define SSF33_CBC_PER_TEST     1
#define SM3_PER_TEST           1
#define SM2_GENKEY_PER_TEST    1
#define SM2_ENC_DEC_PER_TEST   1
#define SM2_SIG_VER_PER_TEST   1
#define SM2_EXH_KEY_PER_TEST   1
#define RSA_GENKEY_PER_TEST    1
#define RSA_EXT_OP_PER_TEST    1
#define RSA_INT_OP_PER_TEST   1

#if SM2_SIG_VER_PER_TEST
	#define SM2_INT_SIG_VER_TEST 1
	#define SM2_EXT_SIG_VER_TEST 1
#endif


#define SM1_L  0x400000   //16 64 128 256 512 1024 2048 10240
#define SM1_N  1  //1000 (1024*1024/SM1_L)

#define SMS4_L  0x400000   //16 64 128 256 512 1024 2048 10240
#define SMS4_N  1  //1000 (1024*1024/SMS4_L)

#define SSF33_L  0x4000000   //16 64 128 256 512 1024 2048 10240
#define SSF33_N  1  //1000 (1024*1024/SMS4_L)

#define SM3_L  0x400000   //16 64 128 256 512 1024 2048 10240
#define SM3_N  1  //1000 (1024*1024/SMS4_L)

#define SM2_KEY_L 96 //Pub:64 Pri:32
#define SM2_KEY_N 100  //1 10 100 1000 10000

#define SM2_EXHKEY_L 32 //session key 32 byte
#define SM2_EXHKEY_N 100  //1 10 100 1000 10000

#define SM2_ED_L 32 //32
#define SM2_ED_N 100  //1 10 100 1000 10000

#define SM2_SV_L 32 //32
#define SM2_SV_N 100 //1 10 100 1000 10000

#define RSA_KEY_L 1152 //N:256,D:256,P:512,Q:640,DPQ:768,DP:896,DQ:1024
#define RSA_KEY_N 10  //1 10 100 1000 10000

#define RSA_EXT_OP_L 256 //32
#define RSA_EXT_OP_N 100  //1 10 100 1000 10000

#define RSA_INT_OP_L 256 //32
#define RSA_INT_OP_N 100  //1 10 100 1000 10000

u32 sm1_ecb_performance_test(void *hSessionHandle);
u32 sm1_cbc_performance_test(void *hSessionHandle);
u32 sms4_ecb_performance_test(void *hSessionHandle);
u32 sms4_cbc_performance_test(void *hSessionHandle);
u32 ssf33_ecb_performance_test(void *hSessionHandle);
u32 ssf33_cbc_performance_test(void *hSessionHandle);
u32 hash_performance_test(void *hSessionHandle);
u32 sm2_genkey_performance_test(void *hSessionHandle);
u32 sm2_ext_enc_dec_performance_test(void *hSessionHandle);
u32 sm2_int_enc_dec_performance_test(void *hSessionHandle);
u32 sm2_sig_ver_performance_test(void *hSessionHandle);
u32 rsa_genkey_performance_test(void *hSessionHandle);
u32 rsa_ext_op_performance_test(void *hSessionHandle);
u32 rsa_int_op_performance_test(void *hSessionHandle);
