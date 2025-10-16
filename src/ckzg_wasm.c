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

static void btox(char *xp, const char *bb, int n) 
{
    int size = n;
    const char xx[]= "0123456789ABCDEF";
    while (--n >= 0) xp[n] = xx[(bb[n>>1] >> ((1 - (n&1)) << 2)) & 0xF];
    xp[size] = 0;
}

KZGSettings *s;

KZGSettings* get_settings_wasm(void) {
    return s;
}


uint32_t load_trusted_setup_wasm(
    uint8_t* g1_monomial_bytes,
    uint8_t* g1_lagrange_bytes,
    uint8_t* g2_monomial_bytes,
    uint64_t precompute) 
{

    uint32_t ret = load_trusted_setup(
        s,
        g1_monomial_bytes,
        NUM_G1_POINTS * BYTES_PER_G1,
        g1_lagrange_bytes,
        NUM_G1_POINTS * BYTES_PER_G1,
        g2_monomial_bytes,
        NUM_G2_POINTS * BYTES_PER_G2,
        precompute
    );
    if (ret == C_KZG_OK) {
       return 0;
    }
    return ret | ((get_last_setting_error()&0xFFFF) << 16);
}

C_KZG_RET load_trusted_setup_file_wasm(FILE *in, uint64_t precompute)
{
    if (s != NULL) {
        free_trusted_setup_wasm();
    }
    s = malloc(sizeof(KZGSettings));
    memset(s, 0, sizeof(KZGSettings));

    return load_trusted_setup_file(s, in, precompute);
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
    Cell cells[CELLS_PER_EXT_BLOB];
    memset(cells, 0, (CELLS_PER_EXT_BLOB) * sizeof(Cell));
    KZGProof proofs[CELLS_PER_EXT_BLOB];
    memset(proofs, 0, CELLS_PER_EXT_BLOB *sizeof(KZGProof));

    const C_KZG_RET ret = compute_cells_and_kzg_proofs(cells, proofs, blob, s);
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


    char *out = malloc(2*(CELLS_PER_EXT_BLOB*sizeof(KZGProof) + CELLS_PER_EXT_BLOB*BYTES_PER_CELL) + 1);


    for (size_t i = 0; i < CELLS_PER_EXT_BLOB; i++) {
        btox((char*)((uintptr_t)out + 2*(i*sizeof(KZGProof))), (const char*)proofs[i].bytes, 2*sizeof(KZGProof));
    }

    uintptr_t offset = 2*(CELLS_PER_EXT_BLOB*sizeof(KZGProof));

    for(size_t i = 0; i < CELLS_PER_EXT_BLOB; i++) {
        btox((char*)((uintptr_t)out + offset + 2* i*BYTES_PER_CELL), (const char*)cells[i].bytes, 2*BYTES_PER_CELL);
    }
    
    return out;
}

char* recover_cells_and_kzg_proofs_wasm(
    const uint64_t *cell_indices,
    const Cell *cells,
    uint64_t num_cells)
{
    Cell recovered_cells[CELLS_PER_EXT_BLOB];
    memset(recovered_cells, 0, CELLS_PER_EXT_BLOB * sizeof(Cell));
    KZGProof proofs[CELLS_PER_EXT_BLOB];
    memset(proofs, 0, CELLS_PER_EXT_BLOB *sizeof(KZGProof));

    const C_KZG_RET ret = recover_cells_and_kzg_proofs(recovered_cells, proofs, cell_indices, cells, num_cells, s);
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

    char *out = malloc(2*(CELLS_PER_EXT_BLOB*sizeof(KZGProof) + CELLS_PER_EXT_BLOB*BYTES_PER_CELL) + 1);


    for (size_t i = 0; i < CELLS_PER_EXT_BLOB; i++) {
        btox((char*)((uintptr_t)out + 2*(i*sizeof(KZGProof))), (const char*)proofs[i].bytes, 2*sizeof(KZGProof));
    }

    uintptr_t offset = 2*(CELLS_PER_EXT_BLOB*sizeof(KZGProof));

    for(size_t i = 0; i < CELLS_PER_EXT_BLOB; i++) {
        btox((char*)((uintptr_t)out + offset + 2*(i*BYTES_PER_CELL)), (const char*)recovered_cells[i].bytes, 2*BYTES_PER_CELL);
    }

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

const char* verify_cell_kzg_proof_wasm(
    const KZGCommitment *commitment,
    const Cell *cells, 
    const KZGProof *proof)
{

    Bytes48 commitments[CELLS_PER_EXT_BLOB];
    uint64_t cell_indices[CELLS_PER_EXT_BLOB];

     for (size_t i = 0; i < CELLS_PER_EXT_BLOB; i++) {
        memcpy(commitments[i].bytes, commitment, BYTES_PER_COMMITMENT);
        cell_indices[i] = i;
    }

    return verify_cell_kzg_proof_batch_wasm(commitments, cell_indices, cells, proof, CELLS_PER_EXT_BLOB);

}

