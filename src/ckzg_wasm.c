#include "ckzg_wasm.h"
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>


static char* invalid_arg(void)
{
    char* msg = malloc(18);
    memcpy(msg, "invalid argument", 17);
    msg[17] = 0;
    return msg;
}

static char* unable_to_allocate_memory(void)
{
    char* msg = malloc(26);
    memcpy(msg, "unable to allocate memory", 25);
    msg[25] = 0;
    return msg;
}

static char* internal_error(void)
{
    char* msg = malloc(15);
    memcpy(msg, "internal error", 14);
    msg[14] = 0;
    return msg;
}

static void btox(char* xp, const char* bb, int n) 
{
    int size = n;
    const char xx[]= "0123456789ABCDEF";
    while (--n >= 0) xp[n] = xx[(bb[n>>1] >> ((1 - (n&1)) << 2)) & 0xF];
    xp[size] = 0;
}

static uint8_t* xtob(char *hex, uint8_t *out, size_t size)
{
    uint8_t bytes[size / 2];
    size_t x = 0;
    size_t y = 0;
    char *ptr = hex;
    while (x < size) {
       char byte[3];
       memcpy(byte, ptr, 2);
       byte[2] = 0;
       char *temp;
       bytes[y] = (uint8_t)strtol(byte, &temp, 16);
       x = x + 2;
       y++;
       ptr = ptr + 2;
    }
    memcpy(out, bytes, size / 2);
    return out;
}
KZGSettings *s;

C_KZG_RET load_trusted_setup_wasm(
    char* g1_monomial,
    size_t g1_monomial_size,
    char* g1_lagrange,
    size_t g1_lagrange_size,
    char* g2_monomial,
    size_t g2_monomial_size,
    uint64_t precompute
    ) 
{
    
    if (s != NULL) {
        free_trusted_setup_wasm();
    }
    s = malloc(sizeof(KZGSettings));
    memset(s, 0, sizeof(KZGSettings));

    uint8_t* g1_monomial_bytes = malloc(g1_monomial_size);
    uint8_t* g1_lagrange_bytes = malloc(g1_lagrange_size);
    uint8_t* g2_monomial_bytes = malloc(g2_monomial_size);
    xtob(g1_monomial, g1_monomial_bytes, g1_monomial_size);
    xtob(g1_lagrange, g1_lagrange_bytes, g1_lagrange_size);
    xtob(g2_monomial, g2_monomial_bytes, g2_monomial_size);
    C_KZG_RET ok = load_trusted_setup(s, g1_monomial_bytes, g1_monomial_size, g1_lagrange_bytes, g1_lagrange_size, g2_monomial_bytes, g2_monomial_size, precompute);
    return ok;
}

void free_trusted_setup_wasm(void)
{
    free_trusted_setup(s);
    free(s);
    s = NULL;
}

char* blob_to_kzg_commitment_wasm(const Blob *blob)
{
    KZGCommitment commit; 
    memset(&commit, 0, sizeof(KZGCommitment));
    const C_KZG_RET ret = blob_to_kzg_commitment(&commit, blob, s);
    switch (ret) {
    case C_KZG_BADARGS:
        return invalid_arg();
    case C_KZG_MALLOC: 
        return unable_to_allocate_memory();
    case C_KZG_OK:
        break;
    case C_KZG_ERROR:
    default: 
        return internal_error();
    }
    const size_t size = sizeof commit.bytes << 1;
    char* hex = malloc(size+1);
    btox(hex, (const char *)commit.bytes, size);
    return hex;
}

char* compute_blob_kzg_proof_wasm(
    const Blob *blob,
    const Bytes48 *commitment_bytes
)
{
    KZGProof proof;
    memset(&proof, 0, sizeof(KZGProof));

    const C_KZG_RET ret = compute_blob_kzg_proof(&proof, blob, commitment_bytes, s);
    switch (ret) {
    case C_KZG_BADARGS:
        return invalid_arg();
    case C_KZG_MALLOC: 
        return unable_to_allocate_memory();
    case C_KZG_OK:
        break;
    case C_KZG_ERROR:
    default: 
        return internal_error();
    }
    const size_t size = sizeof proof.bytes << 1;
    char* hex = malloc(size+1);
    btox(hex, (const char *)proof.bytes, size);
    return hex;
}

const char* verify_blob_kzg_proof_wasm(
    const Blob *blob,
    const Bytes48 *commitment_bytes,
    const Bytes48 *proof_bytes)
{
    bool ok = true;
    const C_KZG_RET ret = verify_blob_kzg_proof(&ok, blob, commitment_bytes, proof_bytes, s);
    switch (ret) {
    case C_KZG_BADARGS: 
        return "invalid argument";
    case C_KZG_MALLOC: 
        return "unable to allocate memory";
    case C_KZG_OK:
        if (ok == 1)
            return "true";
        
        return "false";
    case C_KZG_ERROR:
    default: 
        return "internal error";
    }
    
}

const char* verify_kzg_proof_wasm(
    const Bytes48 *commitment_bytes,
    const Bytes32 *z_bytes,
    const Bytes32 *y_bytes,
    const Bytes48 *proof_bytes) 
{

    bool ok = true;
    const C_KZG_RET ret = verify_kzg_proof(&ok, commitment_bytes, z_bytes, y_bytes, proof_bytes, s);
    switch (ret) {
    case C_KZG_BADARGS:
        return "invalid argument";
    case C_KZG_MALLOC: 
        return "unable to allocate memory";
    case C_KZG_OK:
        if (ok == 1) 
            return "true";
        
        return "false";
    case C_KZG_ERROR:
    default: 
        return "internal error";
    }
}


char* compute_cells_and_kzg_proofs_wasm(const Blob *blob)
{
    Cell cells;
    KZGProof proof;
    memset(&cells, 0, sizeof(Cell));
    memset(&proof, 0, sizeof(KZGProof));

    const C_KZG_RET ret = compute_cells_and_kzg_proofs(&cells, &proof, blob, s);
    switch (ret) {
    case C_KZG_BADARGS: 
        return invalid_arg();
    case C_KZG_MALLOC: 
        return unable_to_allocate_memory();
    case C_KZG_OK:
        break;
    case C_KZG_ERROR:
    default: 
        return internal_error();
    }

    char *out = malloc(sizeof(proof.bytes) + sizeof(cells.bytes) + 1);

    btox(out, (const char *)proof.bytes, sizeof(proof.bytes));
    btox((char*)((uintptr_t)out+ sizeof(proof.bytes)), (const char*)cells.bytes, sizeof(cells.bytes));

    return out;
}

char* recover_cells_and_kzg_proofs_wasm(
    const uint64_t *cell_indices,
    const Cell *cells,
    uint64_t num_cells)
{
    Cell recovered_cells;
    KZGProof proof;
    memset(&recovered_cells, 0, sizeof(Cell));
    memset(&proof, 0, sizeof(KZGProof));

    const C_KZG_RET ret = recover_cells_and_kzg_proofs(&recovered_cells, &proof, cell_indices, cells, num_cells, s);
    switch (ret) {
    case C_KZG_BADARGS: 
        return invalid_arg();
    case C_KZG_MALLOC: 
        return unable_to_allocate_memory();
    case C_KZG_OK:
        break; 
    case C_KZG_ERROR:
    default: 
        return internal_error();
    }

    char *out = malloc(sizeof(proof.bytes) + sizeof(recovered_cells.bytes) + 1);

    btox(out, (const char *)proof.bytes, sizeof(proof.bytes));
    btox((char*)((uintptr_t)out + sizeof(proof.bytes)), (const char*)recovered_cells.bytes, sizeof(recovered_cells.bytes));

    return out;
}


const char* verify_cell_kzg_proof_batch_wasm(
    const Bytes48 *commitments_bytes,
    const uint64_t *cell_indices,
    const Cell *cells,
    const Bytes48 *proofs_bytes,
    uint64_t num_cells)
{
    bool ok = true;
    const C_KZG_RET ret = verify_cell_kzg_proof_batch(&ok, commitments_bytes, cell_indices, cells, proofs_bytes, num_cells, s);
    switch (ret) {
    case C_KZG_BADARGS:
        return "invalid argument";
    case C_KZG_MALLOC:
        return "unable to allocate memory";
    case C_KZG_OK:
        if (ok == 1)
            return "true";

        return "false";
    case C_KZG_ERROR:
    default:
        return "internal error";
    }
}
