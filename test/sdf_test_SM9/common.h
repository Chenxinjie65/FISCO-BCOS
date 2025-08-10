#ifndef __XCSP_UTILS_H__
#define __XCSP_UTILS_H__

#ifdef  __cplusplus
extern "C" {
#endif

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#else
#ifndef _SIZE_T_DEFINED
#define	_SIZE_T_DEFINED
typedef unsigned int size_t; 
#endif
#endif

void c_cleanse(void *ptr, size_t len);
#ifdef _WIN32
wchar_t* c_A2W(const char* a, wchar_t* w);
char* c_W2A(const wchar_t* w, char* a);
#endif
void c_reverse(unsigned char*d, int l);
void c_u32_reverse(unsigned long *d, int l);
void c_reverse_u32(unsigned char* d, int l);
void c_u32_u8(unsigned char* d,unsigned long u);
unsigned long c_u8_u32(unsigned char* d);

char c_GetLetterFromMask(unsigned long ulmask);



#define SECU_FREE(str) \
	if(str)\
	{\
		c_cleanse(str,strlen(str));\
		free(str);\
		str = NULL;\
	}

#ifdef  __cplusplus
}
#endif

#endif
