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

C_KZG_RET load_trusted_setup_wasm(
    char* g1_monomial,
    size_t g1_monomial_size,
    char* g1_lagrange,
    size_t g1_lagrange_size,
    char* g2_monomial,
    size_t g2_monomial_size,
    uint64_t precompute
);

void free_trusted_setup_wasm();

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


char* compute_cells_and_kzg_proofs_wasm(const Blob *blob);

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



#ifdef __cplusplus
}
#endif

#endif /* WASM_H */