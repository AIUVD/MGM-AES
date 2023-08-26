#ifndef CIPHER_H
#define CIPHER_H

//#include "hal.h"
//#include "simpleserial.h"
#include <stdint.h>

//#include <stdlib.h>
//typedef char uint8_t;
typedef uint8_t state_t[4][4];
/*****************************************************************************/
/* Defines:                                                                  */
/*****************************************************************************/
// The number of columns comprising a state in AES. This is a constant in AES. Value=4
#define Nb 4
#define Nk 4        // The number of 32 bit words in a key.
#define Nr 10       // The number of rounds in AES Cipher.


extern uint8_t rin, rout;
extern uint8_t r[16];
extern uint8_t rin1, rout1;
extern uint8_t r1[16];
extern uint8_t sbox[256];
extern uint8_t sboxm[256];
extern uint8_t sbox1[256];
extern uint8_t sboxm1[256];
	 
#define getSBoxValue(num) (sboxm[(num)])

void AddRoundKey(uint8_t, state_t*, const uint8_t*);
void SubBytes(state_t*);
void SubBytes1(state_t*);
uint8_t xtime(uint8_t);
void MixColumns(state_t*, uint8_t);
void Cipher1(state_t*, state_t*,state_t*, state_t*, const uint8_t*);

#endif
