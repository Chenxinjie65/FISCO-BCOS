#include <stdio.h>
#include <string.h>
#include <malloc.h>
#include <time.h>
#include <signal.h>


#define DATA_LEN (0x400000)
#define ALG_SPEED_TEST 1

//sm3 software
//////////////////////////////////////////////////////
#define HASH_BLOCK_SIZE		512
#define ECC_BIGINT32_MAXLEN	8

typedef struct __tagHASH_CTX
{
	unsigned int BitCount;
	unsigned int TempBuf [(HASH_BLOCK_SIZE/32)];
	unsigned int HashValue[ECC_BIGINT32_MAXLEN];
}HASH_CTX;

HASH_CTX pHash_Ctx;

unsigned int IV[8] = {0x7380166F, 0x4914B2B9, 0x172442D7, 0xDA8A0600, 0xA96F30BC, 0x163138AA, 0xE38DEE4D, 0xB0FB0E4E};

unsigned int swap_byte(unsigned int val)
{
	return ((val>>24)&0xFF | ((val>>16)&0xFF)<<8 | ((val>>8)&0xFF)<<16 | (val&0xFF)<<24);
}

void Hash_Init(HASH_CTX *pHash_Ctx, unsigned int *IV)
{
	unsigned short i;
	pHash_Ctx->BitCount = 0;

	for(i=0; i<ECC_BIGINT32_MAXLEN; i++)
	{
		pHash_Ctx->HashValue[i] = IV[i];
	}
	for(i=0; i<(HASH_BLOCK_SIZE>>5); i++)
	{
		pHash_Ctx->TempBuf[i] = 0;
	}
}

int memcp_f(unsigned char* dst, unsigned char* src, unsigned  int size)
{
	unsigned int i;

	for(i=size;i>0;i--)
	{
		*dst = *src;
		dst++;
		src++;
	}
}

void memset_f(unsigned char *buf,unsigned char value,unsigned int bytes)
{
	unsigned int i;
	unsigned char *p=buf;
	for(i=bytes;i>0;i--,p++)
	{
		*p = value;
	}
}

unsigned int LeftRow(unsigned int a, unsigned int len)
{

   return ( a >>(32-len) |(a<<len) );
}

unsigned int P0(unsigned int a)
{
   return ( a ^ LeftRow(a,9) ^ LeftRow(a,17));
}

unsigned int P1(unsigned int a)
{
	return ( a ^ LeftRow(a,15) ^ LeftRow(a,23));
}

unsigned FF0(unsigned int a,unsigned int b,unsigned int c)
{
	return ( a ^ b ^ c );
}

unsigned FF1(unsigned int a,unsigned int b,unsigned int c)
{
	return ( (a & b) | (a & c) | (b & c) );
}

unsigned GG1(unsigned int a,unsigned int b,unsigned int c)
{
	return ( (a & b) | (~a & c));
}

void HASH_256(unsigned int *message, const unsigned int *IV, unsigned int*hash)
{
	unsigned int w[68];
	unsigned int w1[64];
	unsigned int SS1,SS2,TT1,TT2,A,B,CC,D,E,F,G,H;
	char i;

	A = IV[0];
	B = IV[1];
	CC = IV[2];
	D = IV[3];
	E = IV[4];
	F = IV[5];
	G = IV[6];
	H = IV[7];


	for(i=0;i<16;i++)
	{
		w[i] = message[i];
	}
	for(i=16;i<68;i++)
	{
		w[i] = P1(w[i-16] ^ w[i-9] ^ LeftRow(w[i-3],15)) ^ LeftRow(w[i-13],7) ^ w[i-6];
	}

	for(i=0;i<64;i++)
	{
		w1[i] = w[i] ^ w[i+4];
	}

	for(i=0;i<16;i++)
	{
		SS1 = LeftRow((LeftRow(A,12) + E + (LeftRow(0x79cc4519,i))),7);
		SS2 = SS1 ^ LeftRow(A,12);
		TT1 = FF0(A,B,CC) + D + SS2 + w1[i];
		TT2 = FF0(E,F,G) + H + SS1 + w[i];
		D   = CC;
		CC   = LeftRow(B,9);
		B   = A;
		A   = TT1;
		H   = G;
		G   = LeftRow(F,19);
		F   = E;
		E   = P0(TT2);
	}
	for(i=16;i<64;i++)
	{
		SS1 = LeftRow((LeftRow(A,12) + E + (LeftRow(0x7a879d8a,i%32))),7);
		SS2 = SS1 ^ LeftRow(A,12);
		TT1 = FF1(A,B,CC) + D + SS2 + w1[i];
		TT2 = GG1(E,F,G) + H + SS1 + w[i];
		D   = CC;
		CC   = LeftRow(B,9);
		B   = A;
		A   = TT1;
		H   = G;
		G   = LeftRow(F,19);
		F   = E;
		E   = P0(TT2);
	}


	hash[0] = A ^ IV[0];
	hash[1] = B ^ IV[1];
	hash[2] = CC ^ IV[2];
	hash[3] = D ^ IV[3];
	hash[4] = E ^ IV[4];
	hash[5] = F ^ IV[5];
	hash[6] = G ^ IV[6];
	hash[7] = H ^ IV[7];
}

void Hash_Update(HASH_CTX *pHash_Ctx, unsigned char *pData, unsigned int cBData)
{
	unsigned int i, j, index, tmplen;
	unsigned char lastlen=1, slen = 0;
	unsigned char *pbuf;

	pbuf = pData;
	index = (pHash_Ctx->BitCount % 512) >> 3;
	tmplen = cBData + index;
	if(pHash_Ctx->BitCount >= 8)
		lastlen = (pHash_Ctx->BitCount >> 3) % 64;
	pHash_Ctx->BitCount += cBData<<3;

	if(lastlen == 0)
	{
		for(j=0; j<16; j++)
		{
			pHash_Ctx->TempBuf[j] = swap_byte(pHash_Ctx->TempBuf[j]);
		}
		HASH_256(pHash_Ctx->TempBuf, pHash_Ctx->HashValue, pHash_Ctx->HashValue);
	}
	if(tmplen <= 64)
	{
		memcp_f((unsigned char *)pHash_Ctx->TempBuf+index, pbuf, cBData);
	}
	else
	{
		for(i=0; i<tmplen/64; i++)
		{
			memcp_f((unsigned char *)pHash_Ctx->TempBuf+index, pbuf, 64-index);
			pbuf += (64-index);
			cBData -= (64-index+slen);

			for(j=0; j<16; j++)
			{
				pHash_Ctx->TempBuf[j] = swap_byte(pHash_Ctx->TempBuf[j]);
			}

			HASH_256(pHash_Ctx->TempBuf, pHash_Ctx->HashValue, pHash_Ctx->HashValue);
			if(cBData > 64)
			{
				memcp_f((unsigned char *)pHash_Ctx->TempBuf, pbuf, 64);
				index = 64;
				slen = 64;
				pbuf += 64;
			}
			else
			{
				memcp_f((unsigned char *)pHash_Ctx->TempBuf, pbuf, cBData);
				if(cBData == 64)
				{
					break;
				}
			}
		}
	}

}

void SM3_NEW(unsigned int *mes,unsigned int len,const unsigned int *IV,unsigned int *hash)
{
	short i,j,h;
	unsigned int length;
	unsigned int blocklen;
	unsigned char rest;
	unsigned int new_mes[16];
	unsigned int IVU[8];



	for(i=0;i<8;i++)
	{
		IVU[i] = IV[i];
	}


	 if(( (len  & 0x1ff) < 448) && ((len  & 0x1ff) != 0))
	 {
	 	blocklen  =  1;
	 }
	 else
	 {
	 	blocklen  =  2;
	 }

	//length = (len>>14) + 1;
	if( (len & 0x1ff) == 0)
	{
		length = 16;
	}
	else
	{
		length = ((len & 0x1ff) >>5) + 1;
	}
	rest = len & 0x1f;



	for(i=0,j=0,h=0;i<blocklen-1;i++)
	{

		if((len & 0x1ff) < 448)
		{
		    for(j=0;j<16;j++)
		    {
				new_mes[j] = mes[h++];
			}
		}
		else if((len & 0x1ff) == 448)
		{
		    for(j=0;j<14;j++)
		    {
				new_mes[j] = mes[h++];
			}
			new_mes[14] = 0x80000000;
			new_mes[15] = 0;
		}
		else if((len & 0x1ff) == 456)
		{
		    for(j=0;j<14;j++)
		    {
				new_mes[j] = mes[h++];
			}
			new_mes[14] = (mes[h++]&0xff000000) + 0x800000;
			new_mes[15] = 0;
		}
		else if((len & 0x1ff) == 464)
		{
		    for(j=0;j<14;j++)
		    {
				new_mes[j] = mes[h++];
			}
			new_mes[14] = (mes[h++]&0xffff0000) + 0x8000;
			new_mes[15] = 0;
		}
		else if((len & 0x1ff) == 472)
		{
		    for(j=0;j<14;j++)
		    {
				new_mes[j] = mes[h++];
			}
			new_mes[14] = (mes[h++]&0xffffff00) + 0x80;
			new_mes[15] = 0;
		}
		else if((len & 0x1ff) == 480)
		{
		    for(j=0;j<15;j++)
		    {
				new_mes[j] = mes[h++];
			}
			new_mes[15] = 0x80000000;
		}
		else if((len & 0x1ff) == 488)
		{
		    for(j=0;j<15;j++)
		    {
				new_mes[j] = mes[h++];
			}
			new_mes[15] = (mes[h++]&0xff000000) + 0x800000;
		}
		else if((len & 0x1ff) == 496)
		{
		    for(j=0;j<15;j++)
		    {
				new_mes[j] = mes[h++];
			}
			new_mes[15] = (mes[h++]&0xffff0000) + 0x8000;
		}
		else if((len & 0x1ff) == 504)
		{
		    for(j=0;j<15;j++)
		    {
				new_mes[j] = mes[h++];
			}
			new_mes[15] = (mes[h++]&0xffffff00) + 0x80;
		}
		else if((len & 0x1ff) == 512)
		{
		    for(j=0;j<15;j++)
		    {
				new_mes[j] = mes[h++];
			}
			new_mes[15] = mes[h++];
		}

		HASH_256(new_mes,IVU,hash);
	    for(j=0;j<8;j++)
		{
			IVU[j] = hash[j];
		}

	}


    if(blocklen == 1)
    {
		for(j=0,i=0;i<length-1;i++,j++)
		{
			new_mes[j] = mes[i];
		}
		if(rest==0)
		{
			new_mes[j]=0x80000000;
		}
		else if(rest==8)
		{
			new_mes[j]=(mes[length-1] ) | 0x00800000;
		}
		else if(rest==16)
		{
			new_mes[j]=(mes[length-1] ) | 0x00008000;
		}
		else if(rest==24)
		{
			new_mes[j]=(mes[length-1] ) | 0x00000080;
		}

		for(i=j+1;i<15;i++)
		{
			new_mes[i] = 0;
		}
	}
	else if((len & 0x1ff) == 0)
	{
		new_mes[0] = 0x80000000;
		for(i=1;i<15;i++)
		{
			new_mes[i] = 0;
		}
	}
	else
	{
		for(i=0;i<15;i++)
		{
			new_mes[i] = 0;
		}
	}


	new_mes[15] = len;
	HASH_256(new_mes,IVU,hash);
}

void Hash_Final(HASH_CTX *pHash_Ctx)
{
	unsigned int index, i;

	index = (pHash_Ctx->BitCount % 512) >> 3;
	if(index != 0)
		memset_f((unsigned char *)pHash_Ctx->TempBuf+index, 0x00, 64-index);

	for(i=0; i<16; i++)
	{
		pHash_Ctx->TempBuf[i] = swap_byte(pHash_Ctx->TempBuf[i]);
	}

	SM3_NEW(pHash_Ctx->TempBuf, pHash_Ctx->BitCount, pHash_Ctx->HashValue, pHash_Ctx->HashValue);
}
//////////////////////////////////////////

#if 0
int hash_soft_crypto(unsigned char *psrc, unsigned char *pdst,unsigned int len)
{
	unsigned int data[8];
	unsigned char i;
	//sm3 sw
	do{
		Hash_Init(&pHash_Ctx, IV);
		Hash_Update(&pHash_Ctx, (unsigned char *)psrc, len);
		Hash_Final(&pHash_Ctx);
	}while(0);
	
	for(i=0;i<8;i++)
	{
		data[i] = swap_byte(pHash_Ctx.HashValue[i]);
	}
	
	memcpy(pdst,(unsigned char *)data,32);

	return 0;
}
#else
int hash_soft_crypto(unsigned char *psrc, unsigned char *pdst,unsigned int len)
{
	unsigned int data[8];
	unsigned char i;
	HASH_CTX pHash_Ctx_Tmp;
	unsigned int IV_Tmp[8] = {0x7380166F, 0x4914B2B9, 0x172442D7, 0xDA8A0600, 0xA96F30BC, 0x163138AA, 0xE38DEE4D, 0xB0FB0E4E};	
	//sm3 sw
	do{
		Hash_Init(&pHash_Ctx_Tmp, IV_Tmp);
		Hash_Update(&pHash_Ctx_Tmp, (unsigned char *)psrc, len);
		Hash_Final(&pHash_Ctx_Tmp);
	}while(0);
	
	for(i=0;i<8;i++)
	{
		data[i] = swap_byte(pHash_Ctx_Tmp.HashValue[i]);
	}
	
	memcpy(pdst,(unsigned char *)data,32);

	return 0;
}
#endif




