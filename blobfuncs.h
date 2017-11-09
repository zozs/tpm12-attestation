#ifndef BLOBFUNCS_H
#define BLOBFUNCS_H

#include <tss/platform.h>

void print_blob(const char *what, BYTE *blob, long blob_len);
void read_blob(const char *filename, BYTE **output, long *output_len);
void write_blob(const char *filename, BYTE *output, long output_len);

#endif /* BLOBFUNCS_H */
