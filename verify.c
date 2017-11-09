#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <arpa/inet.h>

#include <tss/platform.h>
#include <tss/tss_defines.h>
#include <tss/tss_typedef.h>
#include <tss/tss_structs.h>
#include <tss/tspi.h>
#include <trousers/trousers.h>
#include <tss/tss_error.h>

#include "blobfuncs.h"

#define PCR_MASK_SIZE (3) // Assume 8^3 = 24 PCRs in TPM 1.2
#define PCR_DIGEST_SIZE (20) // SHA-1

struct expected_pcr {
    int pcr_index;
    BYTE pcr_value[PCR_DIGEST_SIZE];
};

int compare_expected_pcr(const void *a, const void *b)
{
    return ((struct expected_pcr *)a)->pcr_index - ((struct expected_pcr *)b)->pcr_index;
}

#define DEBUG 1
// Macro for debug messages
#define DBG(message, tResult) { if(DEBUG) printf("(Line%d, %s) %s returned 0x%08x.%s.\n",   \
        __LINE__ ,__func__ , message, tResult,                                              \
        (char *)Trspi_Error_String(tResult));}

static bool parse_expected_pcrs(BYTE *data, size_t data_len, struct expected_pcr **expected_pcrs, size_t *expected_pcrs_count)
{
    int read = 0;
    const char *s = (const char *)data;

    *expected_pcrs_count = 0;
    *expected_pcrs = NULL;

    int i; /* temporary storage for PCR index */
    BYTE p[20]; /* temporary storage for PCR value */
    while (sscanf(s, "%d=%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx\n%n", &i, &p[0], &p[1], &p[2], &p[3], &p[4], &p[5], &p[6], &p[7], &p[8], &p[9], &p[10], &p[11], &p[12], &p[13], &p[14], &p[15], &p[16], &p[17], &p[18], &p[19], &read) == 21) {
        s += read;
        (*expected_pcrs_count)++;
        *expected_pcrs = realloc(*expected_pcrs, *expected_pcrs_count * sizeof(struct expected_pcr));
        (*expected_pcrs)[*expected_pcrs_count-1].pcr_index = i;
        memcpy((*expected_pcrs)[*expected_pcrs_count-1].pcr_value, p, 20);
    }

    return true;
}

static void print_expected_pcrs(struct expected_pcr *expected_pcrs, size_t expected_pcrs_count)
{
    printf("Expected PCR values:\n");
    for (size_t i = 0; i < expected_pcrs_count; i++) {
        printf("%2d = ", expected_pcrs[i].pcr_index);
        for (int j = 0; j < 20; j++) {
            printf("%02x", expected_pcrs[i].pcr_value[j]);
        }
        printf("\n");
    }
}

static size_t serialize_quote_info(BYTE *nonce, size_t nonce_len, struct expected_pcr *expected_pcrs, size_t expected_pcrs_count, BYTE **data)
{
    // Sort PCRs so that they are in order.
    qsort(expected_pcrs, expected_pcrs_count, sizeof(struct expected_pcr), &compare_expected_pcr);

    // Prepare PCR selection structure with the expected values. Note that we want the serialized version,
    // so we construct it in a sequential piece of memory.
    size_t pcr_selection_size = sizeof(UINT16) + sizeof(BYTE) * PCR_MASK_SIZE;
    TPM_PCR_SELECTION *pcr_selection = calloc(pcr_selection_size, 1);

    pcr_selection->sizeOfSelect = htons(PCR_MASK_SIZE);
    for (size_t i = 0; i < expected_pcrs_count; i++) {
        int pcr_index = expected_pcrs[i].pcr_index;
        ((BYTE *)pcr_selection + sizeof(UINT16))[pcr_index >> 3] |= (1 << (pcr_index & 0x7));
    }

    // Calculate the TPM_PCR_COMPOSITE structure according to sec. 5.4.1 of TPM 1.2 part 2 spec.
    // Since we need the serialized version, we construct this in memory by haxing stuff together
    // so that it is sequential in memory.
    UINT32 pcr_values_size = expected_pcrs_count * PCR_DIGEST_SIZE;
    size_t pcr_composite_size = pcr_selection_size + sizeof(UINT32) + pcr_values_size;
    BYTE *pcr_composite = calloc(pcr_composite_size, 1);

    BYTE *pcr_composite_pos = pcr_composite;

    memcpy(pcr_composite_pos, pcr_selection, pcr_selection_size); // pcr_composite->select = pcr_selection;
    pcr_composite_pos += pcr_selection_size;

    *((UINT32 *)pcr_composite_pos) = htonl(pcr_values_size); // pcr_composite->valueSize = pcr_values_size;
    pcr_composite_pos += sizeof(UINT32);

    for (size_t i = 0; i < expected_pcrs_count; i++) {
        memcpy(pcr_composite_pos, expected_pcrs[i].pcr_value, PCR_DIGEST_SIZE);
        pcr_composite_pos += PCR_DIGEST_SIZE;
    }

    // Now we actually hash the TPM_PCR_COMPOSITE to get the PCR_COMPOSITE_HASH.
    TSS_HCONTEXT hContext;
    TSS_HHASH hHash;
    int result = Tspi_Context_Create(&hContext);
    DBG("Create a context", result);
    result = Tspi_Context_CreateObject(hContext, TSS_OBJECT_TYPE_HASH, TSS_HASH_SHA1, &hHash);
    DBG("Create hash object in context", result);
    // TODO: is this the expected hash we should send in, or the data to be hashed? guess: the data to be hashed.
    result = Tspi_Hash_UpdateHashValue(hHash, pcr_composite_size, pcr_composite);
    DBG("Updating hash value with PCR_COMPOSITE", result);
    UINT32 pcr_composite_hash_size = 0;
    BYTE *pcr_composite_hash = NULL;
    result = Tspi_Hash_GetHashValue(hHash, &pcr_composite_hash_size, &pcr_composite_hash);
    DBG("Calculating hash", result);

    // The signature is calculated over a complete TPM_QUOTE_INFO2 structure, which
    // contains all possible kind of junk. See TPM 1.2 spec Part 3 p. 179 (TPM_Quote2)
    // Again, we need a serialized version in memory to do this. Deep sigh.
    size_t quote_info_size = sizeof(UINT16) + 4 + PCR_DIGEST_SIZE + pcr_selection_size + sizeof(TPM_LOCALITY_SELECTION) + PCR_DIGEST_SIZE;
    TPM_QUOTE_INFO2 *q1 = malloc(quote_info_size); // only works partly, up until pcrSelection.

    q1->tag = htons(TPM_TAG_QUOTE_INFO2);
    q1->fixed[0] = 'Q';
    q1->fixed[1] = 'U';
    q1->fixed[2] = 'T';
    q1->fixed[3] = '2';

    // Copy nonce to q1
    memcpy(q1->externalData.nonce, nonce, nonce_len); // q1->externalData = nonce;

    BYTE *pos = (BYTE *)q1 + sizeof(UINT16) + sizeof(q1->fixed) + sizeof(q1->externalData);
    memcpy(pos, pcr_selection, pcr_selection_size); // q1->infoShort.pcrSelection = pcrSelection;
    pos += pcr_selection_size;

    *((TPM_LOCALITY_SELECTION *)pos) = 0x01; // q1->infoShort.localityAtRelease = 0x01;
    pos += sizeof(TPM_LOCALITY_SELECTION);

    memcpy(pos, pcr_composite_hash, pcr_composite_hash_size); // q1->infoShort.digestAtRelease = pcr_composite_hash;

    // Free memory
    result = Tspi_Context_FreeMemory(hContext, NULL);
    DBG("Tspi Context Free Memory", result);
    result = Tspi_Context_Close(hContext);

    free(pcr_composite);
    free(pcr_selection);

    // Return result.
    *data = (BYTE *)q1;
    return quote_info_size;
}

int main(int argc, char **argv)
{
    if (argc != 5) {
        fprintf(stderr, "usage: %s <aik pub> <quote blob> <nonce blob> <expected pcrs>\n", argv[0]);
        exit(1);
    }

    // Read AIK pub to memory.
    BYTE *aik_pub;
    long aik_pub_len;
    read_blob(argv[1], &aik_pub, &aik_pub_len);
    //print_blob("AIK pub", aik_pub, aik_pub_len);

    // Read quote blob to memory.
    BYTE *quote_blob;
    long quote_blob_len;
    read_blob(argv[2], &quote_blob, &quote_blob_len);
    //print_blob("Quote blob", quote_blob, quote_blob_len);

    // Read nonce to memory.
    BYTE *nonce;
    long nonce_len;
    read_blob(argv[3], &nonce, &nonce_len);
    if (nonce_len != 20) {
        fprintf(stderr, "Unexpected nonce size, should be 20, was %ld\n", nonce_len);
        exit(1);
    }
    print_blob("Nonce", nonce, nonce_len);

    // Expected PCR values. The input file should be on the format: multiple lines where each line is <PCRINDEX>=<20 byte in hex format>
    // for example 6=0123456789abcdeffedc0123456789abcdeffedc
    BYTE *expected_pcr;
    long expected_pcr_len;
    read_blob(argv[4], &expected_pcr, &expected_pcr_len);

    struct expected_pcr *expected_pcrs = NULL;
    size_t expected_pcrs_count = 0;
    if (!parse_expected_pcrs(expected_pcr, expected_pcr_len, &expected_pcrs, &expected_pcrs_count)) {
        fprintf(stderr, "Failed to parse expected PCR values. Invalid input file!\n");
        exit(1);
    }
    print_expected_pcrs(expected_pcrs, expected_pcrs_count);

    // Load public key.
    TSS_RESULT result;
    UINT32 aik_pub_type;
    BYTE aik_pub_blob[1024];
    UINT32 aik_pub_blob_len = 1024;
    result = Tspi_DecodeBER_TssBlob(aik_pub_len, aik_pub, &aik_pub_type, &aik_pub_blob_len, aik_pub_blob);
    DBG("Decode public key", result);

    if (aik_pub_type != TSS_BLOB_TYPE_PUBKEY) {
        fprintf(stderr, "Wrong public key blob type.\n");
        exit(1);
    }

    // Load AIK public key into context.
    TSS_HCONTEXT hContext;
    result = Tspi_Context_Create(&hContext);
    DBG("Create a context", result);
    TSS_HKEY hAIK;
    result = Tspi_Context_CreateObject(hContext, TSS_OBJECT_TYPE_RSAKEY, TSS_KEY_TYPE_IDENTITY | TSS_KEY_SIZE_2048, &hAIK);
    DBG("Create object in context", result);
    result = Tspi_SetAttribData(hAIK, TSS_TSPATTRIB_KEY_BLOB, TSS_TSPATTRIB_KEYBLOB_PUBLIC_KEY, aik_pub_blob_len, aik_pub_blob);
    DBG("Loading public key into context", result);

    // Construct the quote info given the expected PCR values of our registers.
    /*struct expected_pcr expected_pcrs[3] = {
        {0, {0xaa, 0x8d, 0x3e, 0x73, 0x4b, 0x02, 0x11, 0xa5, 0x8d, 0x90, 0x94, 0xa8, 0x8d, 0x7a, 0x15, 0xe7, 0x9d, 0xd8, 0x4b, 0x96}},
        {10, {0x25, 0x94, 0x58, 0x91, 0x24, 0x0d, 0x87, 0x45, 0xcd, 0x7e, 0x27, 0x40, 0xc0, 0xeb, 0x92, 0xf2, 0x6b, 0x0c, 0x56, 0xb7}},
        {14, {0}}
    };*/

    BYTE *quote_info_data = NULL;
    size_t quote_info_data_len = serialize_quote_info(nonce, nonce_len, expected_pcrs, expected_pcrs_count, &quote_info_data);

    // Load quote to verify.
    TSS_HHASH hHash;
    result = Tspi_Context_CreateObject(hContext, TSS_OBJECT_TYPE_HASH, TSS_HASH_SHA1, &hHash);
    DBG("Create hash object in context", result);
    // TODO: is this the expected hash we should send in, or the data to be hashed? guess: the data to be hashed.
    result = Tspi_Hash_UpdateHashValue(hHash, quote_info_data_len, quote_info_data);
    DBG("Setting expected hash", result);
    result = Tspi_Hash_VerifySignature(hHash, hAIK, quote_blob_len, quote_blob);
    DBG("Verifying quote", result);

    free(expected_pcrs);
    free(quote_info_data);
    free(aik_pub);
    free(quote_blob);
    free(nonce);
    free(expected_pcr);

    return 0;
}


/* vim: set ts=4 sw=4 expandtab autoindent: */
