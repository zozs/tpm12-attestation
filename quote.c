#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <tss/platform.h>
#include <tss/tss_defines.h>
#include <tss/tss_typedef.h>
#include <tss/tss_structs.h>
#include <tss/tspi.h>
#include <trousers/trousers.h>
#include <tss/tss_error.h>

#define DEBUG 1
// Macro for debug messages
#define DBG(message, tResult) { if(DEBUG) printf("(Line%d, %s) %s returned 0x%08x.%s.\n",   \
        __LINE__ ,__func__ , message, tResult,                                              \
        (char *)Trspi_Error_String(tResult));}

static bool create_quote(TSS_HCONTEXT hContext, TSS_HTPM hTPM, TSS_HKEY hSRK, BYTE *aik_blob, size_t aik_blob_len, BYTE *nonce, size_t nonce_len, BYTE **quote_data, size_t *quote_len);

int main(int argc, char **argv)
{
    if (argc != 5) {
        fprintf(stderr, "usage: %s <srk secret> <aik blob> <output nonce> <output quote>\n", argv[0]);
        exit(1);
    }

    // read AIK blob to memory.
    BYTE *aik_blob;
    long aik_blob_len;
    read_blob(argv[2], &aik_blob, &aik_blob_len);

    // setup connection to TPM.
    TSS_HCONTEXT hContext = 0;
    TSS_HTPM hTPM = 0;
    TSS_RESULT result;
    TSS_HKEY hSRK = 0;
    TSS_HPOLICY hSRKPolicy = 0;
    TSS_UUID SRK_UUID = TSS_UUID_SRK;
    // By default the SRK secret is 20 zero bytes
    // takeownership -z
    BYTE wks[20];
    memset(wks,0,20);
    // At the beginning
    // Create context and get tpm handle
    result = Tspi_Context_Create(&hContext);
    DBG("Create a context", result);
    result = Tspi_Context_Connect(hContext, NULL);
    DBG("Connect to TPM", result);
    result = Tspi_Context_GetTpmObject(hContext, &hTPM);
    DBG("Get TPM handle", result);
    // Get SRK handle
    // This operation need SRK secret when you takeownership
    // if takeownership -z the SRK is wks by default
    result = Tspi_Context_LoadKeyByUUID(hContext, TSS_PS_TYPE_SYSTEM, SRK_UUID, &hSRK);
    DBG("Get SRK handle", result);
    result = Tspi_GetPolicyObject(hSRK, TSS_POLICY_USAGE, &hSRKPolicy);
    DBG("Get SRK Policy", result);
    
    char *srk_secret = argv[1];
    result = Tspi_Policy_SetSecret(hSRKPolicy, TSS_SECRET_MODE_PLAIN, strlen(srk_secret), (BYTE*)srk_secret);
    DBG("Tspi_Policy_SetSecret", result);
    
    // read pcr value.
    UINT32 pcr_value_len;
    BYTE *pcr_value;
    Tspi_TPM_PcrRead(hTPM, 0, &pcr_value_len, &pcr_value);
    DBG("Read PCR 0", result);
    print_blob("PCR 0", pcr_value, pcr_value_len);

    Tspi_TPM_PcrRead(hTPM, 10, &pcr_value_len, &pcr_value);
    DBG("Read PCR 10", result);
    print_blob("PCR 10", pcr_value, pcr_value_len);

    Tspi_TPM_PcrRead(hTPM, 14, &pcr_value_len, &pcr_value);
    DBG("Read PCR 14", result);
    print_blob("PCR 14", pcr_value, pcr_value_len);

    // prepare for quote, in this case generate a 20 byte nonce. In this case we use the TPMs random number generator.
    BYTE *nonce;
    result = Tspi_TPM_GetRandom(hTPM, 20, &nonce);
    DBG("Get random bytes", result);
    print_blob("Random nonce", nonce, 20);
    
    BYTE *quote_data = NULL;
    size_t quote_len = 0;

    // start by creating quote.
    create_quote(hContext, hTPM, hSRK, aik_blob, aik_blob_len, nonce, 20, &quote_data, &quote_len);

    // Write nonce to file.
    write_blob(argv[3], nonce, 20);

    // Write quote to file.
    write_blob(argv[4], quote_data, quote_len);

    // Print the received quote.
    free(quote_data);
    free(aik_blob);

    // END OF APP
    // Free memory
    result = Tspi_Context_FreeMemory(hContext, NULL);
    DBG("Tspi Context Free Memory", result);
    result = Tspi_Context_Close(hContext);
    DBG("Tspi Context Close", result);
    return 0;
}

static bool is_tss_success(int result, const char *msg)
{
    if (result != TSS_SUCCESS) {
        fprintf(stderr, "Failed to %s, got error: %08x: %s\n", msg, result, (char *)Trspi_Error_String(result));
        return false;
    }
    return true;
}

#define ERRCHECK(msg) do { if (!is_tss_success(result, msg)) { return false; } else { DBG(msg, result); } } while (0)
static bool create_quote(TSS_HCONTEXT hContext, TSS_HTPM hTPM, TSS_HKEY hSRK, BYTE *aik_blob, size_t aik_blob_len, BYTE *nonce, size_t nonce_len, BYTE **quote_data, size_t *quote_len)
{
    int result;
    // We already have an AIK created with tpm-quote-tools, and available as a blob.
    // Now load it into the TPM.
    TSS_HKEY hAIK;
    result = Tspi_Context_LoadKeyByBlob(hContext, hSRK, aik_blob_len, aik_blob, &hAIK);
    ERRCHECK("Load AIK");

    // Select the PCR:s we want to create a quote over.
    TSS_HPCRS hPCRs;
    result = Tspi_Context_CreateObject(hContext, TSS_OBJECT_TYPE_PCRS, TSS_PCRS_STRUCT_INFO_SHORT, &hPCRs);
    ERRCHECK("Create PCR mask object");

    result = Tspi_PcrComposite_SelectPcrIndexEx(hPCRs, 0, TSS_PCRS_DIRECTION_RELEASE);
    ERRCHECK("Selecting PCR 0 in mask");
    result = Tspi_PcrComposite_SelectPcrIndexEx(hPCRs, 10, TSS_PCRS_DIRECTION_RELEASE);
    ERRCHECK("Selecting PCR 10 in mask");
    result = Tspi_PcrComposite_SelectPcrIndexEx(hPCRs, 14, TSS_PCRS_DIRECTION_RELEASE);
    ERRCHECK("Selecting PCR 14 in mask");

    // Perform the actual Quote.
    TSS_VALIDATION valid;
    valid.ulExternalDataLength = nonce_len;
    valid.rgbExternalData = nonce;

    BYTE *version_info;
    UINT32 version_info_len;
    result = Tspi_TPM_Quote2(hTPM, hAIK, false, hPCRs, &valid, &version_info_len, &version_info);
    ERRCHECK("Creating Quote");

#if 0
    write_blob("quote.versioninfo", version_info, version_info_len);
    write_blob("quote.data", valid.rgbData, valid.ulDataLength);
    write_blob("quote.external", valid.rgbExternalData, valid.ulExternalDataLength);
#endif

    *quote_len = valid.ulValidationDataLength;
    *quote_data = malloc(valid.ulValidationDataLength);
    memcpy(*quote_data, valid.rgbValidationData, valid.ulValidationDataLength);

    return true;
}

/* vim: set ts=4 sw=4 expandtab autoindent: */
