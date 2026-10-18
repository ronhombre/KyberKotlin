// Copyright 2026 Ron Lauren Hombre
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//        http://www.apache.org/licenses/LICENSE-2.0
//        
//        and included as LICENSE.txt in this Project.
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#ifndef KYBERKOTLIN_RUST_H
#define KYBERKOTLIN_RUST_H

#include <stddef.h>
#include <stdint.h>

#define KYBERRUST_SUCCESS 0
#define KYBERRUST_INVALID_KEY 1
#define KYBERRUST_RANDOM_FAILURE 2
#define KYBERRUST_UNSUPPORTED_VARIANT 3
#define KYBERRUST_BUFFER_TOO_SMALL 4
#define KYBERRUST_MISMATCHING_VARIANT 5
#define KYBERRUST_INVALID_BUFFER 6

#ifdef __cplusplus
extern "C" {
#endif

int32_t kyberrust_generate(uint32_t variant,
    const uint8_t *seeds, size_t seeds_len, uint8_t *output, size_t output_len);

int32_t kyberrust_generate_pke(uint32_t variant,
    uint8_t *pke_seed, size_t pke_seed_len, uint8_t *output, size_t output_len);

int32_t kyberrust_encapsulate(uint32_t variant,
    const uint8_t *key, size_t key_len,
    uint8_t *output, size_t output_len);

int32_t kyberrust_decapsulate(uint32_t variant,
    const uint8_t *key, size_t key_len, const uint8_t *ciphertext, size_t ciphertext_len,
    uint8_t *output, size_t output_len);

int32_t kyberrust_encrypt(uint32_t variant,
    const uint8_t *key, size_t key_len,
    uint8_t *buffer, size_t buffer_len, uint8_t *output, size_t output_len);

int32_t kyberrust_decrypt(uint32_t variant,
    const uint8_t *key, size_t key_len, const uint8_t *ciphertext, size_t ciphertext_len,
    uint8_t *output, size_t output_len);

#ifdef __cplusplus
}
#endif

#endif
