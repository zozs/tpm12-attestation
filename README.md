# TPM Quote/Verify

## Compilation

Just run `make`. You need TSS installed and setup, and you need to have taken ownership of the TPM and know the SRK usage secret.

## Usage

 * First generate an Attestation Identity Key (AIK)
   * `make create-aik`
   * This generates an AIK and places the private encrypted blob in `aik.blob` and the public part in `aik.pub`
 * Generate a quote. By default this is done over PCRs 0, 10, and 14. It should be simple to modify this in `quote.c`.
   * `./quote <your srk secret> aik.blob quote.nonce quote.blob`
   * This will place the random nonce in `quote.nonce` and the quote (signature) in `quote.blob`
 * Verify the quote. The verifier must know the expected PCR values of the quoted PCRs.
   * `./verify aik.pub quote.blob quote.nonce quote.pcr`
   * Where `quote.pcr` contains the expected PCR measurements with multiple lines of the following format:
   * `0=d58d3e734b9371a58d9092a88b3a15e79dd84bbc`

## License
Licensed under the ISC license. See the file `LICENSE` for details.