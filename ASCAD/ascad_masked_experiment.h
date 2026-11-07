#ifndef ASCAD_MASKED_EXPERIMENT_H
#define ASCAD_MASKED_EXPERIMENT_H

#include <stdint.h>

/* Boolean table-remasking experiment, NOT the original ASCAD AVR algorithm.
 * Random layout: state masks[16] || S-box input/output masks[2] ||
 * independent key masks[16]. Supply fresh OS-CSPRNG bytes for every call.
 * Functional correctness does not establish physical leakage resistance.
 */
#define ASCAD_EXPERIMENT_RANDOM_BYTES 34
/* Prepared masked block state. A context is tied to one 34-byte random input:
 * initialize and prepare it again for each block. Keep volatile accesses to
 * preserve the same explicit share operations. */
typedef struct {
    volatile uint8_t round_key[176];
    volatile uint8_t key_mask[16];
    uint8_t state_random[18];
    volatile uint8_t table[256];
    volatile uint8_t state[16];
    volatile uint8_t state_mask[16];
} ascad_masked_experiment_ctx;

void ascad_masked_experiment_init(ascad_masked_experiment_ctx *ctx,
                                 const uint8_t key[16],
                                 const uint8_t randomness[34]);
/* Prepare the masked S-box table and split plaintext into state shares. */
void ascad_masked_experiment_prepare_state(ascad_masked_experiment_ctx *ctx,
                                           const uint8_t plaintext[16]);
/* Run initial AddRoundKey, ten rounds and final ciphertext unmasking.
 * Call after prepare_state; no key expansion or plaintext sharing occurs here. */
void ascad_masked_experiment_encrypt_state_prepared(ascad_masked_experiment_ctx *ctx,
                                                    uint8_t ciphertext[16]);
/* Convenience API for timing: prepare state then run the AES core. */
void ascad_masked_experiment_encrypt_prepared(const ascad_masked_experiment_ctx *ctx,
                                             const uint8_t plaintext[16],
                                             uint8_t ciphertext[16]);

/* All-in-one API: expands keys online, then performs masked encryption. */
void ascad_masked_experiment_encrypt(const uint8_t key[16],
                                    const uint8_t plaintext[16],
                                    const uint8_t randomness[34],
                                    uint8_t ciphertext[16]);
#endif
