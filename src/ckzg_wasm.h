/**
 * @file wasm.h
 *
 * Minimal interface required loading c-kzg in WASM .
 */
#ifndef WASM_H
#define WASM_H

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include "ckzg.h"

#ifdef __cplusplus
extern "C" {
#endif

uint32_t load_trusted_setup_wasm(
    uint8_t* g1_monomial_bytes,
    uint8_t* g1_lagrange_bytes,
    uint8_t* g2_monomial_bytes,
    uint64_t precompute);

C_KZG_RET load_trusted_setup_file_wasm( FILE *in, uint64_t precompute);

void free_trusted_setup_wasm(void);

// EIP-4844 functions

// C_KZG_RET blob_to_kzg_commitment(KZGCommitment *out, const Blob *blob, const KZGSettings *s);
char* blob_to_kzg_commitment_wasm(const Blob *blob);

char* compute_blob_kzg_proof_wasm(const Blob *blob, const Bytes48 *commitment_bytes);

const char* verify_blob_kzg_proof_wasm(
    const Blob *blob,
    const Bytes48 *commitment_bytes,
    const Bytes48 *proof_bytes
);

const char* verify_kzg_proof_wasm(
    const Bytes48 *commitment_bytes,
    const Bytes32 *z_bytes,
    const Bytes32 *y_bytes,
    const Bytes48 *proof_bytes);

// EIP-7594 functions

// Output is hex
// First 48 * 128 bytes for the proofs
// and 2048 * 128 bytes for the cells
char* compute_cells_and_kzg_proofs_wasm(const Blob *blob);


// Output is hex
// First 48 * 128 bytes for the proofs
// and 2048 * 128 bytes for the cells
char* recover_cells_and_kzg_proofs_wasm(
    const uint64_t* cell_indices,
    const Cell *cells,
    uint64_t num_cells
);

const char* verify_cell_kzg_proof_batch_wasm(
    const Bytes48 *commitments_bytes,
    const uint64_t *cell_indices,
    const Cell *cells,
    const Bytes48 *proofs_bytes,
    uint64_t num_cells);

const char* verify_cell_kzg_proof_wasm(
    const KZGCommitment *commitment,
    const Cell *cells, 
    const KZGProof *proof);

KZGSettings* get_settings_wasm(void);

#ifdef __cplusplus
}
#endif

#endif /* WASM_H */
