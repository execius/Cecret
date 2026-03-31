
#ifndef BYTEBUFF
#define BYTEBUFF


#include "includes.h"
#include "encryption.h" 

typedef struct ByteBuff_s  ByteBuff_t ;
int InitByteBuff(ByteBuff_t **bytebuff,unsigned char *buff,size_t len);
int DestroyByteBuff(ByteBuff_t *bytebuff);
int DestroyByteBuff_Unsafe(ByteBuff_t *bytebuff);
int DupByteBuff(ByteBuff_t **dst,ByteBuff_t *src);


enum ByteBuffErrors {
  ERROR_BUFFDUP_FAILURE = -6000,
  ERROR_BUFFINIT_FAILURE = -6001,
};

#endif
