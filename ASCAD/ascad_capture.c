/* CW303 / SimpleSerial 1.1 capture entry point.
 * k[16] -> z status; m[34] -> z status; p[16] -> r[16], z status.
 * Each accepted p consumes its masks. k and x invalidate old masks.
 */
#include "hal.h"
#include "simpleserial.h"
#include "ascad_masked_experiment.h"
#include <stdint.h>
#include <string.h>

#if SS_VER != SS_VER_1_1
#error "ascad_capture requires SimpleSerial 1.1"
#endif

static uint8_t key[16], masks[ASCAD_EXPERIMENT_RANDOM_BYTES];
static uint8_t key_ready, masks_ready;
static ascad_masked_experiment_ctx ascad_ctx;

static uint8_t set_key(uint8_t *data, uint8_t len)
{
    masks_ready = 0;
    key_ready = 0;
    if (len != sizeof(key)) return 1;
    memcpy(key, data, sizeof(key));
    key_ready = 1;
    return 0;
}

static uint8_t set_masks(uint8_t *data, uint8_t len)
{
    masks_ready = 0;
    if (len != sizeof(masks)) return 1;
    if (!key_ready) return 2;
    memcpy(masks, data, sizeof(masks));
    masks_ready = 1;
    return 0;
}

static uint8_t encrypt_block(uint8_t *data, uint8_t len)
{
    uint8_t plaintext[16], ciphertext[16];
    if (len != sizeof(plaintext)) { masks_ready = 0; return 1; }
    if (!key_ready) return 2;
    if (!masks_ready) return 3;
    masks_ready = 0;
    memcpy(plaintext, data, sizeof(plaintext));

    /* Expand the masked key and split plaintext before the capture window.
     * The trigger then covers initial AddRoundKey, ten rounds and output unmask. */
    ascad_masked_experiment_init(&ascad_ctx, key, masks);
    ascad_masked_experiment_prepare_state(&ascad_ctx, plaintext);
    trigger_high();
    ascad_masked_experiment_encrypt_state_prepared(&ascad_ctx, ciphertext);
    trigger_low();

    memset(&ascad_ctx, 0, sizeof(ascad_ctx));
    memset(masks, 0, sizeof(masks));
    simpleserial_put('r', sizeof(ciphertext), ciphertext);
    return 0;
}

static uint8_t reset_state(uint8_t *data, uint8_t len)
{
    (void)data;
    if (len != 0) return 1;
    trigger_low();
    key_ready = masks_ready = 0;
    memset(key, 0, sizeof(key));
    memset(masks, 0, sizeof(masks));
    return 0;
}

static uint8_t identify(uint8_t *data, uint8_t len)
{
    /* Magic, protocol revision, core ID (1 = Boolean experiment), mask size. */
    uint8_t info[4] = {0xac, 1, 1, ASCAD_EXPERIMENT_RANDOM_BYTES};
    (void)data;
    if (len != 0) return 1;
    simpleserial_put('r', sizeof(info), info);
    return 0;
}

int main(void)
{
    platform_init();
    init_uart();
    trigger_setup();
    trigger_low();
    simpleserial_init();
    simpleserial_addcmd('k', 16, set_key);
    simpleserial_addcmd('m', ASCAD_EXPERIMENT_RANDOM_BYTES, set_masks);
    simpleserial_addcmd('p', 16, encrypt_block);
    simpleserial_addcmd('x', 0, reset_state);
    simpleserial_addcmd('i', 0, identify);
    while (1) simpleserial_get();
}
