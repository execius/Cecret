
#include "bytebuffer.h" 

typedef struct ByteBuff_s {
  unsigned char buff[STRMAX];
  size_t len;
} ByteBuff_t ;

int SanityCheckBuff(const ByteBuff_t *bytebuffer){
  ERROR_CHECK_NULL_LOG(bytebuffer,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
  ERROR_CHECK_SUCCESS_LOG(
      (bytebuffer->len > STRMAX),
      1,
      ERROR_CORRUPTED_BYTEBUFF,
      "username lenght is larger than string lenght limit");
  return ERROR_SUCCESS;
}
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

int DestroyByteBuff_Secure(ByteBuff_t *bytebuff){
  ERROR_CHECK_NULL_LOG(bytebuff,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
  OPENSSL_cleanse(bytebuff, sizeof(ByteBuff_t));
  free(bytebuff);
  return ERROR_SUCCESS;
}

int DestroyByteBuff_NoWipe(ByteBuff_t *bytebuff){
  ERROR_CHECK_NULL_LOG(bytebuff,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
  free(bytebuff);
  return ERROR_SUCCESS;
}

int DupByteBuff(ByteBuff_t **dst,const ByteBuff_t *src){
  ERROR_CHECK_NULL_LOG(src,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
  ERROR_CHECK_NULL_LOG(dst,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
  ERROR_CHECK_SUCCESS_LOG(
      (SanityCheckBuff(src)),
      ERROR_SUCCESS,
      ERROR_CORRUPTED_BYTEBUFF,
      "source byte buffer lenght is corrupted");

  MALLOC_CHECK_NULL_LOG(*dst,
      sizeof(ByteBuff_t),
      ERROR_MEMORY_ALLOCATION,
      "cannot allocate bytebuff");
  memset((*dst)->buff, 0, STRMAX);
  memcpy((*dst)->buff,src->buff,src->len);
  (*dst)->len = src ->len;
  return ERROR_SUCCESS;
}

int GetBuffByteBuff(const ByteBuff_t *bytebuff,unsigned char **buff){
  ERROR_CHECK_NULL_LOG(bytebuff,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
  ERROR_CHECK_NULL_LOG(buff,ERROR_NULL_VALUE_GIVEN,"null value in parameter");

  ERROR_CHECK_SUCCESS_LOG(
      (SanityCheckBuff(bytebuff)),
      ERROR_SUCCESS,
      ERROR_CORRUPTED_BYTEBUFF,
      "byte buffer lenght is corrupted");
  MALLOC_CHECK_NULL_LOG(*buff,
      bytebuff->len,
      ERROR_MEMORY_ALLOCATION,
      "cannot allocate for buff copy");
  memset(*buff, 0, bytebuff->len);
  memcpy(*buff,bytebuff->buff,bytebuff->len);
  return ERROR_SUCCESS;
}

int GetBuffByteBuff_NullTerminated(const ByteBuff_t *bytebuff,unsigned char **buff){
  ERROR_CHECK_NULL_LOG(bytebuff,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
  ERROR_CHECK_NULL_LOG(buff,ERROR_NULL_VALUE_GIVEN,"null value in parameter");

  ERROR_CHECK_SUCCESS_LOG(
      (SanityCheckBuff(bytebuff)),
      ERROR_SUCCESS,
      ERROR_CORRUPTED_BYTEBUFF,
      "byte buffer lenght is corrupted");
  MALLOC_CHECK_NULL_LOG(*buff,
      bytebuff->len+1,
      ERROR_MEMORY_ALLOCATION,
      "cannot allocate for buff copy");
  memset(*buff, 0, bytebuff->len);
  memcpy(*buff,bytebuff->buff,bytebuff->len);
  (*buff)[bytebuff->len] = 0;
  return ERROR_SUCCESS;
}
int GetLenByteBuff(const ByteBuff_t *bytebuff,size_t *len){
  ERROR_CHECK_NULL_LOG(bytebuff,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
  ERROR_CHECK_NULL_LOG(len,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
ERROR_CHECK_SUCCESS_LOG(
      (SanityCheckBuff(bytebuff)),
      ERROR_SUCCESS,
      ERROR_CORRUPTED_BYTEBUFF,
      "byte buffer lenght is corrupted");

  *len = bytebuff->len;
  return ERROR_SUCCESS;
}

int AppendByteBuff(ByteBuff_t *appendee,ByteBuff_t *appended){
  ERROR_CHECK_NULL_LOG(appendee,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
  ERROR_CHECK_NULL_LOG(appended,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
  ERROR_CHECK_SUCCESS_LOG(
      (SanityCheckBuff(appendee)),
      ERROR_SUCCESS,
      ERROR_CORRUPTED_BYTEBUFF,
      "appendee byte buffer lenght is corrupted");
  ERROR_CHECK_SUCCESS_LOG(
      (SanityCheckBuff(appended)),
      ERROR_SUCCESS,
      ERROR_CORRUPTED_BYTEBUFF,
      "appended byte buffer lenght is corrupted");

  ERROR_CHECK_SUCCESS_LOG(
      (appendee->len > STRMAX - appended->len),
      1,
      ERROR_APPENDBUFF_OVERFLOW,
      "the sum of the two buffers' lenghts is larger than maximum size");
  memcpy(appendee->buff + appendee->len,appended->buff,appended->len);
  appendee->len += appended->len;
  return ERROR_SUCCESS;
}

int __AppendstrByteBuff(ByteBuff_t *appendee,const char *appended,size_t len){
  ERROR_CHECK_NULL_LOG(appendee,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
  ERROR_CHECK_NULL_LOG(appended,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
  ERROR_CHECK_SUCCESS_LOG(
      (SanityCheckBuff(appendee)),
      ERROR_SUCCESS,
      ERROR_CORRUPTED_BYTEBUFF,
      "appendee byte buffer lenght is corrupted");

  ERROR_CHECK_SUCCESS_LOG(
      (appendee->len > STRMAX - len),
      1,
      ERROR_APPENDBUFF_OVERFLOW,
      "the sum of the two buffers' lenghts is larger than maximum size");
  memcpy(appendee->buff + appendee->len,appended,len);
  appendee->len += len;
  return ERROR_SUCCESS;
}

