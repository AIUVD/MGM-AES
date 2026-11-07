/*
 * AVR-GCC ABI helper for the measured AES S-box substitution.
 *
 * uint8_t ascad_substitute_sbox_asm(uint8_t share,
 *                                   uint8_t old_mask,
 *                                   uint8_t new_mask,
 *                                   uint8_t im,
 *                                   uint8_t om,
 *                                   const volatile uint8_t *table);
 *
 * On AVR-GCC, the arguments arrive in r24, r22, r20, r18, r16, and r15:r14.
 * The table is in SRAM. The routine preserves callee-saved registers and r1.
 *
 * Operation order follows the original maskedSubBytes output path:
 *   input:  share = x ^ old_mask
 *   index:  share ^ im ^ old_mask = x ^ im
 *   lookup: SBOX(x) ^ om
 *   output: lookup ^ new_mask ^ om = SBOX(x) ^ new_mask
 *
 * This ports the XOR order only; it does not port the original routine's
 * randomized byte order or its explicit memory-bus clearing operations.
 */

	.text
	.global ascad_substitute_sbox_asm
	.type ascad_substitute_sbox_asm, @function
ascad_substitute_sbox_asm:
	/* Convert the input share to the table's input mask without forming x. */
	eor r24, r18                 /* share ^ im */
	eor r24, r22                 /* share ^ im ^ old_mask = x ^ im */

	/* Read precomputed table[x ^ im] = SBOX(x) ^ om. */
	movw r30, r14                /* Z = table */
	add r30, r24
	adc r31, r1
	ld r24, Z
	nop                          /* Separate the table result from mask handling. */

	/* Match original order: add new state mask, then cancel output mask. */
	eor r24, r20                 /* SBOX(x) ^ om ^ new_mask */
	eor r24, r16                 /* SBOX(x) ^ new_mask */
	ret
	.size ascad_substitute_sbox_asm, .-ascad_substitute_sbox_asm
