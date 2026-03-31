
#include "bytebuffer.h" 

typedef struct ByteBuff_s {
  unsigned char buff[STRMAX];
  size_t len;
} ByteBuff_t ;

int InitByteBuff(ByteBuff_t **bytebuff,unsigned char *buff,size_t len){
  ERROR_CHECK_NULL_LOG(bytebuff,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
  ERROR_CHECK_NULL_LOG(buff,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
  ERROR_CHECK_SUCCESS_LOG(
      (len > STRMAX),
      1,
      ERROR_LEN_VAR_LARGER_THAN_STRMAX,
      "username lenght is larger than string lenght limit");

  MALLOC_CHECK_NULL_LOG(*bytebuff,
      sizeof(ByteBuff_t),
      ERROR_MEMORY_ALLOCATION,
      "cannot allocate bytebuff");

  memset((*bytebuff)->buff, 0, STRMAX);
  memcpy((*bytebuff)->buff,buff,len);
  (*bytebuff)->len = len;
  return ERROR_SUCCESS;
}

int DestroyByteBuff(ByteBuff_t *bytebuff){
  ERROR_CHECK_NULL_LOG(bytebuff,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
  OPENSSL_cleanse(bytebuff, sizeof(ByteBuff_t));
  free(bytebuff);
  return ERROR_SUCCESS;
}

int DestroyByteBuff_Unsafe(ByteBuff_t *bytebuff){
  ERROR_CHECK_NULL_LOG(bytebuff,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
  free(bytebuff);
  return ERROR_SUCCESS;
}

int DupByteBuff(ByteBuff_t **dst,ByteBuff_t *src){
  ERROR_CHECK_NULL_LOG(src,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
  ERROR_CHECK_NULL_LOG(dst,ERROR_NULL_VALUE_GIVEN,"null value in parameter");

  MALLOC_CHECK_NULL_LOG(*dst,
      sizeof(ByteBuff_t),
      ERROR_MEMORY_ALLOCATION,
      "cannot allocate bytebuff");
  memset((*dst)->buff, 0, STRMAX);
  memcpy((*dst)->buff,src->buff,src->len);
  (*dst)->len = src ->len;
  return ERROR_SUCCESS;
}

