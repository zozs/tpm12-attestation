/*
 * Convert strings from the native encoding to UTF-16LE.
 * Copyright (C) 2010 The MITRE Corporation
 *
 * This program is free software: you can redistribute it and/or
 * modify it under the terms of the BSD License as published by the
 * University of California.
 */

#if defined HAVE_CONFIG_H
#include "config.h"
#endif
#include <stddef.h>

#if defined HAVE_ICONV_H
#include <stdlib.h>
#include <string.h>
#include <iconv.h>
#include <langinfo.h>

/* Use POSIX 1003.1 functions to convert input to UTF-16LE.  Returns
   NULL on error, otherwise, a malloc'd string using the new
   encoding. */
char *toutf16le(char *src)
{
  if (!src)
    return NULL;
  iconv_t cd = iconv_open("UTF-16LE", nl_langinfo(CODESET));
  if (cd == (iconv_t)-1)
    return NULL;
  size_t n = strlen(src);
  size_t len = 2*(n + 1);	/* Max output size */
  char *ans = malloc(len);
  if (!ans) {			/* No memory.  Yikes! */
    iconv_close(cd);
    return NULL;
  }
  char *inbuf = src;
  size_t inbytesleft = n + 1;
  char *outbuf = ans;
  size_t outbytesleft = len;
  size_t rc = iconv(cd, &inbuf, &inbytesleft, &outbuf, &outbytesleft);
  iconv_close(cd);
  if (rc == (size_t)-1 || inbytesleft != 0) {
    free(ans);
    return NULL;
  }
  return ans;
}
#else
char *toutf16le(char *src)
{
  return NULL;		 /* Always fail when iconv is not available */
}
#endif

/* Returns the number of bytes in a UTF16le encoded string. */
size_t utf16lelen(const char *src)
{
  size_t len = 0;
  for (; src[len] || src[len + 1]; len += 2);
  return len;
}
