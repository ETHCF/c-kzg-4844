#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "ckzg_wasm.h"
#include "test/tests.h"

// Helper function to convert hex string to bytes
static void hex_to_bytes(const char *hex, uint8_t *out, size_t out_len) {
    const char *pos = hex;
    // Skip "0x" prefix if present
    if (pos[0] == '0' && (pos[1] == 'x' || pos[1] == 'X')) {
        pos += 2;
    }

    for (size_t i = 0; i < out_len; i++) {
        sscanf(pos, "%2hhx", &out[i]);
        pos += 2;
    }
}

// // Helper function to convert bytes to uppercase hex string
// static void bytes_to_hex(const uint8_t *bytes, size_t len, char *out) {
//     for (size_t i = 0; i < len; i++) {
//         sprintf(out + (i * 2), "%02X", bytes[i]);
//     }
//     out[len * 2] = '\0';
// }

// Helper function to compare hex strings (case-insensitive)
static int hex_compare(const char *hex1, const char *hex2) {
    const char *p1 = hex1;
    const char *p2 = hex2;

    // Skip "0x" prefix if present
    if (p1[0] == '0' && (p1[1] == 'x' || p1[1] == 'X')) p1 += 2;
    if (p2[0] == '0' && (p2[1] == 'x' || p2[1] == 'X')) p2 += 2;

    return strcasecmp(p1, p2);
}

static void test_blob_to_kzg_commitment_and_verify_proof(void) {
    printf("Running test: generate kzg commitments and verify proofs\n");

    // Create a blob with first two bytes set to 0x01, 0x02
    Blob blob;
    memset(&blob, 0, sizeof(Blob));
    blob.bytes[0] = 0x01;
    blob.bytes[1] = 0x02;

    // Test blob_to_kzg_commitment
    char* commitment_hex = blob_to_kzg_commitment_wasm(&blob);
    printf("Commitment: %s\n", commitment_hex);

    // Expected commitment (uppercase)
    const char* expected_commitment = "AB87358A111C3CD9DA8AADF4B414E9F6BE5AC83D923FB70D8D27FEF1E2690B4CAD015B23B8C058881DA78A05C62B1173";

    // Compare (case-insensitive)
    assert(hex_compare(commitment_hex, expected_commitment) == 0);
    printf("✓ Commitment matches expected value\n");

    // Convert commitment hex to Bytes48
    Bytes48 commitment_bytes;
    hex_to_bytes(commitment_hex, commitment_bytes.bytes, 48);

    // Test compute_blob_kzg_proof
    char* proof_hex = compute_blob_kzg_proof_wasm(&blob, &commitment_bytes);
    printf("Proof: %s\n", proof_hex);

    // Expected proof
    const char* expected_proof = "8DD951EDB4E0DF1779C29D28B835A2CC8B26EBF69A38D7D9AFADD0EB8A4CBFFD9DB1025FD253E91E00A9904F109E81E3";

    // Compare (case-insensitive)
    assert(hex_compare(proof_hex, expected_proof) == 0);
    printf("✓ Proof matches expected value\n");

    // Convert proof hex to Bytes48
    Bytes48 proof_bytes;
    hex_to_bytes(proof_hex, proof_bytes.bytes, 48);

    // Test verify_blob_kzg_proof
    const char* verify_result = verify_blob_kzg_proof_wasm(&blob, &commitment_bytes, &proof_bytes);
    printf("Verification result: %s\n", verify_result);

    assert(strcmp(verify_result, "true") == 0);
    printf("✓ Proof verification succeeded\n");

    // Clean up
    free(commitment_hex);
    free(proof_hex);

    printf("✓ Test passed: generate kzg commitments and verify proofs\n\n");
}

static void test_verify_kzg_proof_with_points(void) {
    printf("Running test: verify kzg proofs with points\n");

    // Test data from the JavaScript test
    const char* proof_hex = "0xc00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
    const char* commitment_hex = "0xc00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
    const char* z_hex = "0x623ce31cf9759a5c8daf3a357992f9f3dd7f9339d8998bc8e68373e54f00b75e";
    const char* y_hex = "0x0000000000000000000000000000000000000000000000000000000000000000";

    // Convert hex strings to bytes
    Bytes48 commitment_bytes;
    Bytes48 proof_bytes;
    Bytes32 z_bytes;
    Bytes32 y_bytes;

    hex_to_bytes(commitment_hex, commitment_bytes.bytes, 48);
    hex_to_bytes(proof_hex, proof_bytes.bytes, 48);
    hex_to_bytes(z_hex, z_bytes.bytes, 32);
    hex_to_bytes(y_hex, y_bytes.bytes, 32);

    // Verify the KZG proof
    const char* verify_result = verify_kzg_proof_wasm(
        &commitment_bytes,
        &z_bytes,
        &y_bytes,
        &proof_bytes
    );

    printf("Verification result: %s\n", verify_result);

    assert(strcmp(verify_result, "true") == 0);
    printf("✓ KZG proof with points verification succeeded\n");

    printf("✓ Test passed: verify kzg proofs with points\n\n");
}

static void test_recover_cells_and_kzg_proofs__succeeds_random_blob(void) {
    C_KZG_RET ret;
    Blob blob;
    const size_t num_partial_cells = CELLS_PER_EXT_BLOB / 2;
    uint64_t cell_indices[CELLS_PER_EXT_BLOB];
    Cell cells[CELLS_PER_EXT_BLOB];
    Cell partial_cells[num_partial_cells];
    KZGProof proofs[CELLS_PER_EXT_BLOB];

    /* Get a random blob */
    get_rand_blob(&blob);


    /* Get the cells and proofs */
    ret = compute_cells_and_kzg_proofs(cells, proofs, &blob, get_settings_wasm());
    assert(ret == C_KZG_OK);

    /* Get the cells and proofs */
    char* proof_and_cells = compute_cells_and_kzg_proofs_wasm(&blob);
    
    /* Erase half of the cells */
    for (size_t i = 0; i < num_partial_cells; i++) {
        cell_indices[i] = i * 2;
        memcpy(&partial_cells[i], &cells[cell_indices[i]], sizeof(Cell));
    }

    char* restored_proof_and_cells = recover_cells_and_kzg_proofs_wasm(cell_indices, partial_cells, num_partial_cells);
    assert(strcmp(proof_and_cells, restored_proof_and_cells) == 0);

    assert(strlen(proof_and_cells) == 2*(48 + CELLS_PER_EXT_BLOB*BYTES_PER_CELL));
   
    free(proof_and_cells);
    free(restored_proof_and_cells);
}


int main(void) {
    printf("=== C-KZG-4844 WASM Test Suite ===\n\n");

    // Load trusted setup from file
    printf("Loading trusted setup...\n");
    FILE *fp = fopen("./trusted_setup.txt", "r");
    if (fp == NULL) {
        fprintf(stderr, "Error: Could not open trusted_setup.txt\n");
        fprintf(stderr, "Please ensure the file exists in the current directory\n");
        return 1;
    }

    C_KZG_RET ret = load_trusted_setup_file_wasm(fp, 0);
    fclose(fp);

    if (ret != C_KZG_OK) {
        fprintf(stderr, "Error: Failed to load trusted setup (error code: %d)\n", ret);
        return 1;
    }
    printf("✓ Trusted setup loaded successfully\n\n");

    // Run tests
    test_blob_to_kzg_commitment_and_verify_proof();
    test_verify_kzg_proof_with_points();
    test_recover_cells_and_kzg_proofs__succeeds_random_blob();

    // Clean up
    free_trusted_setup_wasm();
    printf("✓ Trusted setup freed\n");

    printf("=== All tests passed! ===\n");
    return 0;
}
