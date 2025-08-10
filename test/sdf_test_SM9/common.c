
#include <string.h>
#include <stdlib.h>
#include "common.h"

unsigned char cleanse_ctr = 0;
void c_cleanse(void *ptr, size_t len)
{
	unsigned char *p = ptr;
	size_t loop = len, ctr = cleanse_ctr;
	while(loop--)
	{
		*(p++) = (unsigned char)ctr;
		ctr += (17 + ((size_t)p & 0xF));
	}
	p=memchr(ptr, (unsigned char)ctr, len);
	if(p)
		ctr += (63 + (size_t)p);
	cleanse_ctr = (unsigned char)ctr;
	memset(ptr,0,len);
}

#ifdef _WIN32
wchar_t* c_A2W(const char* a, wchar_t* w)
{
	int len =  MultiByteToWideChar(CP_ACP, 0, a, -1, NULL, 0);
	if(len == 0)
		return NULL;

	if(w == NULL)
		w = malloc(sizeof(wchar_t)*(len+1));
	MultiByteToWideChar(CP_ACP, 0, a, -1, w, len);

	return w;
}

char* c_W2A(const wchar_t* w, char* a)
{
	int len = WideCharToMultiByte(CP_ACP, 0, w, -1, NULL, 0,0,0);
	if(len == 0)
		return NULL;

	if(a == NULL)
		a = malloc(sizeof(char)*(len+1));
	WideCharToMultiByte(CP_ACP, 0, w, -1, a, len,0,0);

	return a;
}
#endif

void c_reverse(unsigned char *d, int l)
{
	unsigned char t;	
    int m,i;				

    m = l/2;

    for(i=0; i<m; i++)
    {
        t = d[i];
        d[i] = d[l-i-1];
        d[l-i-1] = t;
    }
}

void c_u32_reverse(unsigned long *d, int l)
{
	unsigned long t;	
	int m,i;				

	m = l/2;

	for(i=0; i<m; i++)
	{
		t = d[i];
		d[i] = d[l-i-1];
		d[l-i-1] = t;
	}
}

void c_reverse_u32(unsigned char* d, int l)
{
	int i;
	for (i=0;i<l/4;i++)
	{
		c_reverse(d,4);
		d += 4;
	}
}

void c_u32_u8(unsigned char* d, unsigned long u)
{
	*(d+0) = (unsigned char)((u>>24)&0xff);
	*(d+1) = (unsigned char)((u>>16)&0xff);
	*(d+2) = (unsigned char)((u>>8)&0xff);
	*(d+3) = (unsigned char)(u & 0xff);
}

unsigned long c_u8_u32(unsigned char* d)
{
	unsigned long u = 0;

	u += (unsigned long)d[0]<<24;
	u += (unsigned long)d[1]<<16;
	u += (unsigned long)d[2]<<8;
	u += (unsigned long)d[3];

	return u;
}

char c_GetLetterFromMask(unsigned long ulmask)
{
	int i;

	for (i = 0; i < 26; ++i)
	{
		if (ulmask & 0x1)
			break;
		ulmask = ulmask >> 1;
	}

	return (i + 'A');
}
