#include "hal.h"
#include "simpleserial.h"
#include <stdint.h>
#include <stdlib.h>
#include "cipher.h"

struct AES_ctx
{
	uint8_t RoundKey[176];
};

uint8_t ekey[16] = {0};
uint8_t ptx[52] = {0};
uint8_t rkx[16] = {0};
struct AES_ctx ctx;

/*****************************************************************************/
/* Defines:                                                                  */
/*****************************************************************************/
// The number of columns comprising a state in AES. This is a constant in AES. Value=4
#define Nb 4
#define Nk 4        // The number of 32 bit words in a key.
#define Nr 10       // The number of rounds in AES Cipher.

/*****************************************************************************/
/* Private variables:                                                        */
/*****************************************************************************/
// state - array holding the intermediate results during decryption.
typedef uint8_t state_t[4][4];
// The round constant word array, Rcon[i], contains the values given by 
// x to the power (i-1) being powers of x (x is denoted as {02}) in the field GF(2^8)
static const uint8_t Rcon[11] = {
	0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36 };

/*****************************************************************************/
/* Private functions:                                                        */
/*****************************************************************************/

#define getSBoxValue(num) (sbox[(num)])

// This function produces Nb(Nr+1) round keys. The round keys are used in each round to decrypt the states. 
static void KeyExpansion(uint8_t* RoundKey, const uint8_t* Key)
{
	unsigned i, j, k;
	uint8_t tempa[4]; // Used for the column/row operations

					  // The first round key is the key itself.
	for (i = 0; i < Nk; ++i)
	{
		RoundKey[(i * 4) + 0] = Key[(i * 4) + 0];
		RoundKey[(i * 4) + 1] = Key[(i * 4) + 1];
		RoundKey[(i * 4) + 2] = Key[(i * 4) + 2];
		RoundKey[(i * 4) + 3] = Key[(i * 4) + 3];
	}

	// All other round keys are found from the previous round keys.
	for (i = Nk; i < Nb * (Nr + 1); ++i)
	{
		{
			k = (i - 1) * 4;
			tempa[0] = RoundKey[k + 0];
			tempa[1] = RoundKey[k + 1];
			tempa[2] = RoundKey[k + 2];
			tempa[3] = RoundKey[k + 3];

		}

		if (i % Nk == 0)
		{
			// This function shifts the 4 bytes in a word to the left once.
			// [a0,a1,a2,a3] becomes [a1,a2,a3,a0]

			// Function RotWord()
			{
				const uint8_t u8tmp = tempa[0];
				tempa[0] = tempa[1];
				tempa[1] = tempa[2];
				tempa[2] = tempa[3];
				tempa[3] = u8tmp;
			}

			// SubWord() is a function that takes a four-byte input word and 
			// applies the S-box to each of the four bytes to produce an output word.

			// Function Subword()
			{
				tempa[0] = getSBoxValue(tempa[0]);
				tempa[1] = getSBoxValue(tempa[1]);
				tempa[2] = getSBoxValue(tempa[2]);
				tempa[3] = getSBoxValue(tempa[3]);
			}

			tempa[0] = tempa[0] ^ Rcon[i / Nk];
		}
#if defined(AES256) && (AES256 == 1)
		if (i % Nk == 4)
		{
			// Function Subword()
			{
				tempa[0] = getSBoxValue(tempa[0]);
				tempa[1] = getSBoxValue(tempa[1]);
				tempa[2] = getSBoxValue(tempa[2]);
				tempa[3] = getSBoxValue(tempa[3]);
			}
		}
#endif
		j = i * 4; k = (i - Nk) * 4;
		RoundKey[j + 0] = RoundKey[k + 0] ^ tempa[0];
		RoundKey[j + 1] = RoundKey[k + 1] ^ tempa[1];
		RoundKey[j + 2] = RoundKey[k + 2] ^ tempa[2];
		RoundKey[j + 3] = RoundKey[k + 3] ^ tempa[3];
	}
}

void AES_init_ctx(struct AES_ctx* ctx, const uint8_t* key)
{
	KeyExpansion(ctx->RoundKey, key);
}



// Cipher is the main function that encrypts the PlainText.
static void Cipher(state_t* state, const uint8_t* RoundKey)
{
	uint8_t round = 0;
	uint8_t state1[4][4] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
	uint8_t state2[4][4] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
	uint8_t state3[4][4] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
	uint8_t state4[4][4] = { 0x76, 0x54, 0x32, 0x10, 0xfe, 0xdc, 0xba, 0x98, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67 };

	uint8_t rk[4][4] = { 0x78,0x78,0x78,0x78,0x78,0x78,0x78,0x78,0x78,0x78,0x78,0x78,0x78,0x78,0x78,0x78 };
	//uint8_t rk[4][4] = { 0x87,0x87,0x87,0x87,0x87,0x87,0x87,0x87,0x87,0x87,0x87,0x87,0x87,0x87,0x87,0x87 };

	int seed = 0;
	for (int i = 0; i < 16; i++) {
		seed += ekey[i] * ekey[i];
	}
	srand(seed);
	rin = rand() % 256;
	srand(rand());
	rout = rand() % 256;
	for (int i = 0; i < 16; i++) {
		srand(rand());
		r[i] = rand() % 256;
	}
	for (int i = 0; i < 16; i++) {
		srand(rand());
		r1[i] = rand() % 256;
	}
	srand(rand());
	rin1 = rand() % 256;
	srand(rand());
	rout1 = rand() % 256;

	for (int i = 0; i < 256; i++) {
		sboxm[i] = sbox[i ^ rin] ^ rout;
		sboxm1[i] = sbox1[i ^ rin1] ^ rout1;
	}
	for (int i = 0; i < 4; i++) {
		for (int j = 0; j < 4; j++) {
			state2[i][j] = (*state)[i][j] ^ r1[4 * i + j];
			state3[i][j] = r1[4 * i + j];
			(*state)[i][j] ^= r[4 * i + j];
			state1[i][j] = r[4 * i + j];
		}
	}
	// Add the First round key to the state before starting the rounds.
	AddRoundKey(0, state, RoundKey);
	for (int i = 0; i < 4; i++) {
		for (int j = 0; j < 4; j++) {
			(*state)[i][j] ^= state1[i][j];
		}
	}
	for (int i = 0; i < 4; i++) {
		for (int j = 0; j < 4; j++) {
			state2[i][j] = (*state)[i][j] ^ rin1;
			state2[i][j] ^= rin;
		}
	}
	trigger_high();
	Cipher1(state, (state_t *)state1, (state_t *)state2, (state_t *)state3, RoundKey);
}


/*****************************************************************************/
/* Public functions:                                                         */
/*****************************************************************************/

void AES_ECB_encrypt(const struct AES_ctx* ctx, uint8_t* buf)
{
	// The next function call encrypts the PlainText with the Key using AES algorithm.
	Cipher((state_t*)buf, ctx->RoundKey);
}

uint8_t get_key(uint8_t* kx, uint8_t len)
{
    for (uint8_t i = 0; i < 16; i++)
    {
        ekey[i] = kx[i];
    }
    uint8_t tmp[16]={0x0d, 0x0e, 0x0f, 0x00, 0x09, 0x0a, 0x0b, 0x0c, 0x05, 0x06, 0x07, 0x08, 0x01, 0x02, 0x03, 0x04};
    AES_init_ctx(&ctx, tmp);   
    simpleserial_put('r', 16, ekey); 
    return 0x00;
}

uint8_t get_rk(uint8_t* rk, uint8_t len)
{
    for (uint8_t i = 0; i < 16; i++)
    {
        rkx[i] = rk[i];
    }
	return 0x00;
}

uint8_t get_pt(uint8_t* pt, uint8_t len)
{
    for (uint8_t i = 0; i < 16; i++)
    {
        ptx[i] = pt[i];
    }
	
    for (uint8_t i = 0; i < 16; i++)
    {
	ptx[i] ^= rkx[i];
    }
    AES_ECB_encrypt(&ctx, ptx);
    trigger_low();
    for (uint8_t i = 16; i < 32; i++)
    {
        ptx[i] = r[i-16];
    }
    ptx[32] = rin;
    ptx[33] = rout;
    for (uint8_t i = 34; i < 50; i++)
    {
        ptx[i] = r1[i-34];
    }
    ptx[50] = rin1;
    ptx[51] = rout1;
    simpleserial_put('r', 52, ptx);
	return 0x00;
}

uint8_t reset(uint8_t* x, uint8_t len)
{
    // Reset key here if needed
	return 0x00;
}



int main(void)
{

    platform_init();
    init_uart();
    trigger_setup();

	simpleserial_init();
    simpleserial_addcmd('k', 16, get_key);
	simpleserial_addcmd('m', 16,  get_rk);
    simpleserial_addcmd('p', 16,  get_pt);
    simpleserial_addcmd('x',  0,   reset);
    while(1)
        simpleserial_get();
}
