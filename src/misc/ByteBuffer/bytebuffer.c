
#include "bytebuffer.h" 

typedef struct ByteBuff_s {
  unsigned char *buff;
  size_t len;
} ByteBuff_t ;

int bytebuffsize(void) {
  return sizeof(ByteBuff_t);
}
int InitByteBuff(ByteBuff_t **bytebuff,unsigned char *buff,size_t len){
  ERROR_CHECK_NULL_LOG(bytebuff,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
  ERROR_CHECK_NULL_LOG(buff,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
  int rc = 0;
  ERROR_CHECK_SUCCESS_LOG(
      (len < 1),
      1,
      ERROR_LEN_VAR_TOO_SMALL,
      "username lenght is too small < 1");

  MALLOC_CHECK_NULL_LOG(*bytebuff,
      sizeof(ByteBuff_t),
      ERROR_MEMORY_ALLOCATION,
      "cannot allocate bytebuff");

  MALLOC_CHECK_NULL_SET_RC_GOTO((*bytebuff)->buff,
      len,
      ERROR_MEMORY_ALLOCATION,
      "cannot allocate bytebuff buffer",
      rc,
      cleanup);

  memset((*bytebuff)->buff, 0, len);
  memcpy((*bytebuff)->buff,buff,len);
  (*bytebuff)->len = len;
  return ERROR_SUCCESS;
cleanup :
  if (*bytebuff) {
    if ((*bytebuff)->buff) {
      OPENSSL_cleanse((*bytebuff)->buff,(*bytebuff)->len);
      free((*bytebuff)->buff);
      (*bytebuff)->buff = NULL;
    } 
    OPENSSL_cleanse(*bytebuff,sizeof(ByteBuff_t));
    free(*bytebuff);
    *bytebuff = NULL;
  } 
  return rc;

}

int DestroyByteBuff_Secure(ByteBuff_t *bytebuff){
  ERROR_CHECK_NULL_LOG(bytebuff,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
  ERROR_CHECK_NULL_LOG(bytebuff->buff,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
  OPENSSL_cleanse(bytebuff->buff, bytebuff->len);
  OPENSSL_cleanse(bytebuff, sizeof(ByteBuff_t));
  free(bytebuff->buff);
  free(bytebuff);
  return ERROR_SUCCESS;
}

int DestroyByteBuff_NoWipe(ByteBuff_t *bytebuff){
  ERROR_CHECK_NULL_LOG(bytebuff,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
  free(bytebuff->buff);
  free(bytebuff);
  return ERROR_SUCCESS;
}

int DupByteBuff(ByteBuff_t **dst,const ByteBuff_t *src){
  ERROR_CHECK_NULL_LOG(src,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
  ERROR_CHECK_NULL_LOG(src->buff,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
  ERROR_CHECK_NULL_LOG(dst,ERROR_NULL_VALUE_GIVEN,"null value in parameter");

  ERROR_CHECK_SUCCESS_LOG(
      (InitByteBuff(dst,src->buff,src->len)),
      ERROR_SUCCESS,
      ERROR_BUFFINIT_FAILURE,
      "failed to inittialize user");
  ;
  return ERROR_SUCCESS;
}

int GetBuffByteBuff(const ByteBuff_t *bytebuff,unsigned char **buff){
  ERROR_CHECK_NULL_LOG(bytebuff,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
  ERROR_CHECK_NULL_LOG(buff,ERROR_NULL_VALUE_GIVEN,"null value in parameter");

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
  ERROR_CHECK_NULL_LOG(bytebuff->buff,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
  ERROR_CHECK_NULL_LOG(buff,ERROR_NULL_VALUE_GIVEN,"null value in parameter");

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

  *len = bytebuff->len;
  return ERROR_SUCCESS;
}

int AppendByteBuff(ByteBuff_t *appendee,ByteBuff_t *appended){
  ERROR_CHECK_NULL_LOG(appendee,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
  ERROR_CHECK_NULL_LOG(appended,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
  ERROR_CHECK_NULL_LOG(appended->buff,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
  ERROR_CHECK_NULL_LOG(appendee->buff,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
  if (appendee->len > SIZE_MAX - appended->len)
    return ERROR_APPENDBUFF_OVERFLOW;
  void *tmp = realloc(appendee->buff,appendee->len + appended->len);
  if (!tmp){
    return ERROR_MEMORY_ALLOCATION;
  }
  appendee->buff = tmp;
  memcpy(appendee->buff + appendee->len,appended->buff,appended->len);
  appendee->len += appended->len;
  return ERROR_SUCCESS;
}

int __AppendstrByteBuff(ByteBuff_t *appendee,const char *appended,size_t len){
  ERROR_CHECK_NULL_LOG(appendee,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
  ERROR_CHECK_NULL_LOG(appendee->buff,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
  ERROR_CHECK_NULL_LOG(appended,ERROR_NULL_VALUE_GIVEN,"null value in parameter");

  if (appendee->len > SIZE_MAX - len)
    return ERROR_APPENDBUFF_OVERFLOW;
  void *tmp = realloc(appendee->buff,appendee->len + len);
  if (!tmp){
    return ERROR_MEMORY_ALLOCATION;
  }
  appendee->buff = tmp;
  memcpy(appendee->buff + appendee->len,appended,len);
  appendee->len += len;
  return ERROR_SUCCESS;
}

