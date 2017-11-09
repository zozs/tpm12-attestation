#include "blobfuncs.h"

#include <stdio.h>

void print_blob(const char *what, BYTE *blob, long blob_len)
{
    printf("%s len: %ld\n", what, blob_len);
    for (long i = 0; i < blob_len; i++) {
        printf("%02lx ", (unsigned long)blob[i]);
    }
    printf("\n");
}

void read_blob(const char *filename, BYTE **output, long *output_len)
{
    FILE *fin = fopen(filename, "rb");
    if (!fin) {
        fprintf(stderr, "Failed to open file %s\n", filename);
        exit(1);
    }
    fseek(fin, 0, SEEK_END);
    long blob_len = ftell(fin);
    rewind(fin);
    if (blob_len <= 0) {
        fprintf(stderr, "Input file %s looks empty\n", filename);
        exit(1);
    }

    BYTE *blob = malloc(blob_len);
    if (fread(blob, 1, blob_len, fin) != blob_len) {
        fprintf(stderr, "Failed to read input file %s\n", filename);
        exit(1);
    }
    fclose(fin);

    *output = blob;
    *output_len = blob_len;
}

void write_blob(const char *filename, BYTE *output, long output_len)
{
    FILE *fout = fopen(filename, "wb");
    if (!fout) {
        fprintf(stderr, "Failed to open file %s for writing\n", filename);
        exit(1);
    }
    if (fwrite(output, 1, output_len, fout) != output_len) {
        fprintf(stderr, "Failed to write data to file %s\n", filename);
        exit(1);
    }
    fclose(fout);
}

/* vim: set ts=4 sw=4 expandtab autoindent: */