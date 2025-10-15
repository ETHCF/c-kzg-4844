/*
 * Copyright 2024 Benjamin Edgington
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#pragma once

#ifndef SETUP_SETUP_H
#define SETUP_SETUP_H

#include "common/ret.h"
#include "setup/settings.h"

#include <stdio.h> /* For FILE */

/** The number of bytes in a g1 point. */
#define BYTES_PER_G1 48

/** The number of bytes in a g2 point. */
#define BYTES_PER_G2 96

/** The number of g1 points in a trusted setup. */
#define NUM_G1_POINTS FIELD_ELEMENTS_PER_BLOB

/** The number of g2 points in a trusted setup. */
#define NUM_G2_POINTS 65


typedef enum {
    C_SETTING_OK = 0,  /**< Success! */
    C_SETTING_ERR_UNKNOWN, /**< An unknown error occurred. */
    C_SETTING_BAD_PRECOMPUTE, /**< The supplied precompute value is invalid. */
    C_SETTING_BAD_G1_MON_LEN, /**< The supplied g1 monomial byte length is incorrect. */
    C_SETTING_BAD_G1_LAG_LEN, /**< The supplied g1 lagrange byte length is incorrect. */
    C_SETTING_BAD_G2_MON_LEN, /**< The supplied g2 monomial byte length is incorrect. */
    C_SETTING_BAD_G1_MON, /**< The supplied g1 mon omial bytes are invalid. */
    C_SETTING_BAD_G1_LAG, /**< The supplied g1 lagrange bytes are invalid. */
    C_SETTING_BAD_G2_MON, /**< The supplied g2 monomial bytes are invalid. */
    C_SETTING_BAD_LAGRANGE, /**< The supplied trusted setup is not in Lagrange form. */
    C_SETTING_BAD_COMPUTE_ROOTS, /**< Could not compute roots of unity. */
    C_SETTING_BAD_BIT_REVERSE, /**< Could not bit-reverse the g1 lagrange points. */
    C_SETTING_BAD_FK20_INIT, /**< Could not initialize the FK20 settings. */
} C_SETTING_ERR;

C_SETTING_ERR get_last_setting_error(void);


////////////////////////////////////////////////////////////////////////////////////////////////////
// Public Functions
////////////////////////////////////////////////////////////////////////////////////////////////////

#ifdef __cplusplus
extern "C" {
#endif

C_KZG_RET load_trusted_setup(
    KZGSettings *out,
    const uint8_t *g1_monomial_bytes,
    uint64_t num_g1_monomial_bytes,
    const uint8_t *g1_lagrange_bytes,
    uint64_t num_g1_lagrange_bytes,
    const uint8_t *g2_monomial_bytes,
    uint64_t num_g2_monomial_bytes,
    uint64_t precompute
);

C_KZG_RET load_trusted_setup_file(KZGSettings *out, FILE *in, uint64_t precompute);

void free_trusted_setup(KZGSettings *s);

#ifdef __cplusplus
}
#endif

#endif /* SETUP_SETUP_H */
