/*
    This file is part of the ChipWhisperer Example Targets
    Copyright (C) 2012-2017 NewAE Technology Inc.

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "hal.h"
#include "simpleserial.h"
#include <stdint.h>
#include <stdlib.h>

struct AES_ctx
{
	uint8_t RoundKey[176];
};

uint8_t ekey[16] = {0};
uint8_t ptx[16] = {0};
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

// The lookup-tables are marked const so they can be placed in read-only storage instead of RAM
// The numbers below can be computed dynamically trading ROM for RAM - 
// This can be useful in (embedded) bootloader applications, where ROM is often limited.
uint8_t sbox[256] = {
	//0     1    2      3     4    5     6     7      8    9     A      B    C     D     E     F
	0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
	0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
	0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
	0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
	0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
	0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
	0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
	0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
	0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
	0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
	0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
	0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
	0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
	0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
	0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
	0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16 };

uint8_t sbox1[4096] = {
	0xDF,0xCA,0xAD,0x5A,0xE2,0x94,0x9C,0x17,0x61,0xA2,0x27,0xA4,0x6C,0x4A,0x93,0x83,
	0x8F,0x7B,0xCB,0x02,0xAA,0x65,0xD8,0x58,0x7D,0x3B,0x08,0x54,0xDF,0xE9,0x41,0x45,
	0xDD,0x36,0x2D,0x1F,0x7C,0x73,0xAF,0x03,0x67,0x74,0xE5,0x1C,0x51,0x24,0x80,0x4E,
	0x56,0xFC,0xF5,0x70,0x31,0x75,0x2A,0x1E,0x0E,0x91,0xAC,0xF8,0xF0,0x49,0xE8,0xD5,
	0x0E,0x91,0xAC,0xF8,0xF0,0x49,0xE8,0xD5,0x56,0xFC,0xF5,0x70,0x31,0x75,0x2A,0x1E,
	0x67,0x74,0xE5,0x1C,0x51,0x24,0x80,0x4E,0xDD,0x36,0x2D,0x1F,0x7C,0x73,0xAF,0x03,
	0x7D,0x3B,0x08,0x54,0xDF,0xE9,0x41,0x45,0x8F,0x7B,0xCB,0x02,0xAA,0x65,0xD8,0x58,
	0x61,0xA2,0x27,0xA4,0x6C,0x4A,0x93,0x83,0xDF,0xCA,0xAD,0x5A,0xE2,0x94,0x9C,0x17,
	0x8C,0x95,0x3E,0xE3,0xEF,0xC3,0xFF,0x01,0x48,0x06,0xF7,0x30,0xDB,0xBB,0x5B,0x1B,
	0xFB,0x9F,0xC8,0x35,0xEC,0x7F,0xB8,0x57,0xA7,0x16,0x20,0x05,0xB7,0x87,0x85,0x4F,
	0x81,0x07,0x6D,0xB3,0xCF,0xC7,0x39,0xC2,0xB2,0xED,0x19,0x04,0xD9,0x96,0x12,0x77,
	0x0F,0x15,0x43,0x72,0xC6,0x68,0xC5,0x23,0xD6,0x2E,0xD1,0xC4,0x79,0xDC,0x1A,0xCE,
	0xD6,0x2E,0xD1,0xC4,0x79,0xDC,0x1A,0xCE,0x0F,0x15,0x43,0x72,0xC6,0x68,0xC5,0x23,
	0xB2,0xED,0x19,0x04,0xD9,0x96,0x12,0x77,0x81,0x07,0x6D,0xB3,0xCF,0xC7,0x39,0xC2,
	0xA7,0x16,0x20,0x05,0xB7,0x87,0x85,0x4F,0xFB,0x9F,0xC8,0x35,0xEC,0x7F,0xB8,0x57,
	0x48,0x06,0xF7,0x30,0xDB,0xBB,0x5B,0x1B,0x8C,0x95,0x3E,0xE3,0xEF,0xC3,0xFF,0x01 ,
	0xD5,0xC0,0x56,0xA1,0x0D,0x7B,0xBD,0x36,0x93,0x50,0xE8,0x6B,0x63,0x45,0x5E,0x4E,
	0x33,0xC7,0xB6,0x7F,0xC6,0x09,0xEF,0x6F,0x42,0x04,0x59,0x05,0xD1,0xE7,0xF7,0xF3,
	0x7C,0x97,0xAA,0x98,0x7A,0x75,0x38,0x94,0xE5,0xF6,0x08,0xF1,0x8D,0xF8,0x6A,0xA4,
	0x3F,0x95,0x90,0x15,0xFB,0xBF,0x81,0xB5,0x84,0x1B,0x9A,0xCE,0x85,0x3C,0x12,0x2F,
	0x1B,0x84,0xCE,0x9A,0x3C,0x85,0x2F,0x12,0x95,0x3F,0x15,0x90,0xBF,0xFB,0xB5,0x81,
	0xF6,0xE5,0xF1,0x08,0xF8,0x8D,0xA4,0x6A,0x97,0x7C,0x98,0xAA,0x75,0x7A,0x94,0x38,
	0x04,0x42,0x05,0x59,0xE7,0xD1,0xF3,0xF7,0xC7,0x33,0x7F,0xB6,0x09,0xC6,0x6F,0xEF,
	0x50,0x93,0x6B,0xE8,0x45,0x63,0x4E,0x5E,0xC0,0xD5,0xA1,0x56,0x7B,0x0D,0x36,0xBD,
	0x54,0x4D,0x1C,0xC1,0x0B,0x27,0x52,0xAC,0x65,0x2B,0x73,0xB4,0x82,0xE2,0x71,0x31,
	0x7E,0x1A,0xA6,0x5B,0x77,0xE4,0x4F,0xA0,0xBE,0x0F,0xA9,0x8C,0x07,0x37,0x9F,0x55,
	0xD5,0x53,0x83,0x5D,0x88,0x80,0xBA,0x41,0xFC,0xA3,0xCA,0xD7,0x92,0xDD,0xEA,0x8F,
	0x3A,0x20,0x28,0x19,0x30,0x9E,0xC4,0x22,0x14,0xEC,0xDA,0xCF,0xC3,0x66,0x68,0xBC,
	0xEC,0x14,0xCF,0xDA,0x66,0xC3,0xBC,0x68,0x20,0x3A,0x19,0x28,0x9E,0x30,0x22,0xC4,
	0xA3,0xFC,0xD7,0xCA,0xDD,0x92,0x8F,0xEA,0x53,0xD5,0x5D,0x83,0x80,0x88,0x41,0xBA,
	0x0F,0xBE,0x8C,0xA9,0x37,0x07,0x55,0x9F,0x1A,0x7E,0x5B,0xA6,0xE4,0x77,0xA0,0x4F,
	0x2B,0x65,0xB4,0x73,0xE2,0x82,0x31,0x71,0x4D,0x54,0xC1,0x1C,0x27,0x0B,0xAC,0x52 ,
	0xB9,0x5D,0xCB,0xCD,0x01,0xB9,0x7F,0x3A,0x70,0x8E,0x36,0x88,0xC6,0x22,0x39,0xEB,
	0xC8,0xFD,0x8C,0x84,0x65,0xF1,0x17,0xCC,0x07,0x2F,0x72,0x40,0xAF,0x21,0x31,0x8D,
	0x09,0xC4,0xF9,0xED,0x6E,0xF0,0xBD,0x80,0x34,0x48,0xB6,0x20,0xC0,0x83,0x11,0xE9,
	0xD2,0x74,0x71,0xF8,0x37,0x12,0x2C,0x79,0x2B,0x08,0x89,0x61,0xB1,0x87,0xA9,0x1B,
	0x89,0x61,0x2B,0x08,0xA9,0x1B,0xB1,0x87,0x71,0xF8,0xD2,0x74,0x2C,0x79,0x37,0x12,
	0xB6,0x20,0x34,0x48,0x11,0xE9,0xC0,0x83,0xF9,0xED,0x09,0xC4,0xBD,0x80,0x6E,0xF0,
	0x72,0x40,0x07,0x2F,0x31,0x8D,0xAF,0x21,0x8C,0x84,0xC8,0xFD,0x17,0xCC,0x65,0xF1,
	0x36,0x88,0x70,0x8E,0x39,0xEB,0xC6,0x22,0xCB,0xCD,0xB9,0x5D,0x7F,0x3A,0x01,0xB9,
	0xE0,0x03,0x52,0x75,0xE4,0x81,0xF4,0x43,0x4D,0xAA,0xF2,0x9C,0x26,0x35,0xA6,0x95,
	0xE7,0x68,0xD4,0xC2,0x0A,0xF5,0x5E,0xDD,0xDE,0xFF,0x59,0xEC,0x50,0xCA,0x62,0x02,
	0xB7,0x8B,0x5B,0x3F,0x54,0x98,0xA2,0x9D,0x77,0xB5,0xDC,0x5C,0x67,0x9B,0xAC,0x7A,
	0x93,0xD7,0xDF,0xB0,0x06,0x5F,0x05,0x14,0x49,0x78,0x4E,0x92,0xD1,0xBC,0xB2,0xAE,
	0x4E,0x92,0x49,0x78,0xB2,0xAE,0xD1,0xBC,0xDF,0xB0,0x93,0xD7,0x05,0x14,0x06,0x5F,
	0xDC,0x5C,0x77,0xB5,0xAC,0x7A,0x67,0x9B,0x5B,0x3F,0xB7,0x8B,0xA2,0x9D,0x54,0x98,
	0x59,0xEC,0xDE,0xFF,0x62,0x02,0x50,0xCA,0xD4,0xC2,0xE7,0x68,0x5E,0xDD,0x0A,0xF5,
	0xF2,0x9C,0x4D,0xAA,0xA6,0x95,0x26,0x35,0x52,0x75,0xE0,0x03,0xF4,0x43,0xE4,0x81 ,
	0x42,0xA6,0xC1,0xC7,0x20,0x98,0x90,0xD5,0xBF,0x41,0xC4,0x7A,0x0B,0xEF,0x36,0xE4,
	0xB5,0x80,0x30,0x38,0x52,0xC6,0x7B,0xA0,0x56,0x7E,0x4D,0x7F,0x19,0x97,0x3F,0x83,
	0x8E,0x43,0x58,0x4C,0xF9,0x67,0xBB,0x86,0xD9,0xA5,0x34,0xA2,0x2A,0x69,0xCD,0x35,
	0xB7,0x11,0x18,0x91,0x9C,0xB9,0xE6,0xB3,0x1D,0x3E,0x03,0xEB,0x4B,0x7D,0xDC,0x6E,
	0xEB,0x03,0x3E,0x1D,0x6E,0xDC,0x7D,0x4B,0x91,0x18,0x11,0xB7,0xB3,0xE6,0xB9,0x9C,
	0xA2,0x34,0xA5,0xD9,0x35,0xCD,0x69,0x2A,0x4C,0x58,0x43,0x8E,0x86,0xBB,0x67,0xF9,
	0x7F,0x4D,0x7E,0x56,0x83,0x3F,0x97,0x19,0x38,0x30,0x80,0xB5,0xA0,0x7B,0xC6,0x52,
	0x7A,0xC4,0x41,0xBF,0xE4,0x36,0xEF,0x0B,0xC7,0xC1,0xA6,0x42,0xD5,0x90,0x98,0x20,
	0xC2,0x21,0x8A,0xAD,0x49,0x2C,0x10,0xA7,0xC9,0x2E,0xDF,0xB1,0x0C,0x1F,0xFF,0xCC,
	0x89,0x06,0x51,0x47,0xFD,0x02,0xC5,0x46,0x57,0x76,0x40,0xF5,0x4A,0xD0,0xD2,0xB2,
	0x59,0x65,0x0F,0x6B,0xD7,0x1B,0xE5,0xDA,0xA4,0x66,0x92,0x12,0x9F,0x63,0xE7,0x31,
	0xF8,0xBC,0xEA,0x85,0x07,0x5E,0xF3,0xE2,0x42,0x73,0x8C,0x50,0xA3,0xCE,0x08,0x14,
	0x50,0x8C,0x73,0x42,0x14,0x08,0xCE,0xA3,0x85,0xEA,0xBC,0xF8,0xE2,0xF3,0x5E,0x07,
	0x12,0x92,0x66,0xA4,0x31,0xE7,0x63,0x9F,0x6B,0x0F,0x65,0x59,0xDA,0xE5,0x1B,0xD7,
	0xF5,0x40,0x76,0x57,0xB2,0xD2,0xD0,0x4A,0x47,0x51,0x06,0x89,0x46,0xC5,0x02,0xFD,
	0xB1,0xDF,0x2E,0xC9,0xCC,0xFF,0x1F,0x0C,0xAD,0x8A,0x21,0xC2,0xA7,0x10,0x2C,0x49 ,
	0x73,0x83,0x84,0xA9,0x4E,0xDD,0xB5,0xE4,0xA2,0x9C,0x5F,0xDE,0xAF,0x74,0xEB,0xF9,
	0x9A,0xBE,0x56,0xD5,0xBF,0xA0,0x45,0x8F,0xEE,0x99,0x91,0x2A,0x4C,0x4B,0xD8,0x3B,
	0xFD,0xB1,0xCB,0xE9,0x5C,0xF4,0x49,0xF5,0x14,0x59,0x54,0xAA,0x22,0x09,0x31,0xF8,
	0x2D,0x24,0x0C,0x47,0x4A,0xAD,0xD3,0x29,0x1C,0x7C,0xDA,0x42,0xE2,0xA4,0x9E,0x6F,
	0xE2,0xA4,0x9E,0x6F,0x1C,0x7C,0xDA,0x42,0x4A,0xAD,0xD3,0x29,0x2D,0x24,0x0C,0x47,
	0x22,0x09,0x31,0xF8,0x14,0x59,0x54,0xAA,0x5C,0xF4,0x49,0xF5,0xFD,0xB1,0xCB,0xE9,
	0x4C,0x4B,0xD8,0x3B,0xEE,0x99,0x91,0x2A,0xBF,0xA0,0x45,0x8F,0x9A,0xBE,0x56,0xD5,
	0xAF,0x74,0xEB,0xF9,0xA2,0x9C,0x5F,0xDE,0x4E,0xDD,0xB5,0xE4,0x73,0x83,0x84,0xA9,
	0x7D,0x58,0xA8,0xFA,0x1E,0x0E,0x69,0x18,0x7B,0x41,0x3C,0x55,0xE8,0xFC,0x90,0x7E,
	0xAE,0xD4,0x67,0x03,0xB9,0x34,0x17,0x61,0x2F,0x37,0x36,0x80,0x3F,0xA6,0x93,0xCA,
	0x66,0xF3,0x27,0x94,0x28,0x33,0x73,0xE5,0x8A,0xD0,0x5A,0x6C,0xE1,0xAB,0x51,0x1F,
	0xAC,0x75,0xBC,0xE7,0x65,0x08,0x3A,0xB6,0x70,0xF0,0x40,0x2C,0xDF,0x02,0x8B,0x26,
	0xDF,0x02,0x8B,0x26,0x70,0xF0,0x40,0x2C,0x65,0x08,0x3A,0xB6,0xAC,0x75,0xBC,0xE7,
	0xE1,0xAB,0x51,0x1F,0x8A,0xD0,0x5A,0x6C,0x28,0x33,0x73,0xE5,0x66,0xF3,0x27,0x94,
	0x3F,0xA6,0x93,0xCA,0x2F,0x37,0x36,0x80,0xB9,0x34,0x17,0x61,0xAE,0xD4,0x67,0x03,
	0xE8,0xFC,0x90,0x7E,0x7B,0x41,0x3C,0x55,0x1E,0x0E,0x69,0x18,0x7D,0x58,0xA8,0xFA ,
	0x9C,0x6C,0xA5,0x88,0x44,0xD7,0x4E,0x1F,0xAD,0x93,0x92,0x13,0x5D,0x86,0x24,0x36,
	0xF6,0xD2,0x61,0xE2,0x03,0x1C,0x38,0xF2,0xE0,0x97,0x27,0x9C,0x73,0x74,0x89,0x6A,
	0xFB,0xB7,0x5C,0x7E,0xFD,0x55,0xCE,0x72,0xC8,0x85,0xBE,0x40,0xA0,0x8B,0xDC,0x15,
	0xE7,0xEE,0xA7,0xEC,0x23,0xC4,0xB6,0x4C,0x69,0x09,0x20,0xB8,0x68,0x2E,0xA8,0x59,
	0x2E,0x68,0x59,0xA8,0x09,0x69,0xB8,0x20,0xC4,0x23,0x4C,0xB6,0xEE,0xE7,0xEC,0xA7,
	0x8B,0xA0,0x15,0xDC,0x85,0xC8,0x40,0xBE,0x55,0xFD,0x72,0xCE,0xB7,0xFB,0x7E,0x5C,
	0x74,0x73,0x6A,0x89,0x97,0xE0,0x9C,0x27,0x1C,0x03,0xF2,0x38,0xD2,0xF6,0xE2,0x61,
	0x86,0x5D,0x36,0x24,0x93,0xAD,0x13,0x92,0xD7,0x44,0x1F,0x4E,0x6C,0x9C,0x88,0xA5,
	0x99,0xBC,0x05,0x57,0xC6,0xD6,0x4B,0x3A,0x22,0x18,0x16,0x7F,0xC5,0xD1,0x14,0xFA,
	0x35,0x4F,0x90,0xF4,0x3C,0xB1,0x79,0x0F,0x9F,0x87,0x2C,0x9A,0x26,0xBF,0x1A,0x43,
	0x21,0xB4,0xA4,0x17,0x7C,0x67,0x9D,0x0B,0xC1,0x9B,0xA2,0x94,0xAF,0xE5,0x82,0xCC,
	0x5A,0x83,0xBD,0xE6,0x50,0x3D,0x51,0xDD,0xCA,0x4A,0x32,0x5E,0x1D,0xC0,0x80,0x2D,
	0xC0,0x1D,0x2D,0x80,0x4A,0xCA,0x5E,0x32,0x3D,0x50,0xDD,0x51,0x83,0x5A,0xE6,0xBD,
	0xE5,0xAF,0xCC,0x82,0x9B,0xC1,0x94,0xA2,0x67,0x7C,0x0B,0x9D,0xB4,0x21,0x17,0xA4,
	0xBF,0x26,0x43,0x1A,0x87,0x9F,0x9A,0x2C,0xB1,0x3C,0x0F,0x79,0x4F,0x35,0xF4,0x90,
	0xD1,0xC5,0xFA,0x14,0x18,0x22,0x7F,0x16,0xD6,0xC6,0x3A,0x4B,0xBC,0x99,0x57,0x05 ,
	0x90,0xAE,0x67,0x84,0x28,0x4A,0xD3,0x73,0x08,0xF4,0xF5,0xB6,0xBE,0x58,0xFA,0xD5,
	0x55,0x2A,0x99,0x41,0xF8,0x26,0x02,0x09,0x9E,0x51,0xE1,0xE2,0x36,0x5F,0xA2,0x2F,
	0xEF,0x32,0xD9,0x6A,0x88,0x06,0x9D,0x07,0x85,0xFE,0xC5,0x0D,0x71,0x35,0x62,0xC4,
	0x2B,0x43,0x0A,0x20,0xCE,0x25,0x57,0xA1,0x5D,0xB2,0x9B,0x8C,0xC7,0x3D,0xBB,0xF6,
	0xBB,0xF6,0xC7,0x3D,0x9B,0x8C,0x5D,0xB2,0x57,0xA1,0xCE,0x25,0x0A,0x20,0x2B,0x43,
	0x62,0xC4,0x71,0x35,0xC5,0x0D,0x85,0xFE,0x9D,0x07,0x88,0x06,0xD9,0x6A,0xEF,0x32,
	0xA2,0x2F,0x36,0x5F,0xE1,0xE2,0x9E,0x51,0x02,0x09,0xF8,0x26,0x99,0x41,0x55,0x2A,
	0xFA,0xD5,0xBE,0x58,0xF5,0xB6,0x08,0xF4,0xD3,0x73,0x28,0x4A,0x67,0x84,0x90,0xAE,
	0x76,0x1A,0xA3,0xB8,0x72,0x98,0x05,0x8E,0x86,0xCF,0xC1,0xDB,0xED,0x50,0x95,0xD2,
	0x48,0x5E,0x81,0x89,0xA5,0xC3,0x0B,0x96,0xC8,0x7A,0xD1,0xCD,0x46,0x4F,0xEA,0x23,
	0xFD,0xAC,0xBC,0xCB,0x1E,0xBF,0x45,0x69,0x34,0xDD,0xE4,0x61,0x24,0xF3,0x94,0x47,
	0x6C,0x42,0x7C,0xD0,0xF9,0xCA,0xA6,0x74,0xD8,0x90,0xE8,0x4C,0x40,0x54,0x14,0x70,
	0x14,0x70,0x40,0x54,0xE8,0x4C,0xD8,0x90,0xA6,0x74,0xF9,0xCA,0x7C,0xD0,0x6C,0x42,
	0x94,0x47,0x24,0xF3,0xE4,0x61,0x34,0xDD,0x45,0x69,0x1E,0xBF,0xBC,0xCB,0xFD,0xAC,
	0xEA,0x23,0x46,0x4F,0xD1,0xCD,0xC8,0x7A,0x0B,0x96,0xA5,0xC3,0x81,0x89,0x48,0x5E,
	0x95,0xD2,0xED,0x50,0xC1,0xDB,0x86,0xCF,0x05,0x8E,0x72,0x98,0xA3,0xB8,0x76,0x1A ,
	0xB1,0x8F,0x88,0x6B,0xD3,0xB1,0xD9,0x79,0xC5,0x39,0xFA,0xB9,0x71,0x97,0x08,0x27,
	0x62,0x1D,0xF5,0x2D,0x85,0x5B,0xBE,0xB5,0x28,0xE7,0xEF,0xEC,0x67,0x0E,0x9D,0x10,
	0x78,0xA5,0xDF,0x6C,0x0F,0x81,0x3C,0xA6,0x6F,0x14,0x19,0xD1,0x9C,0xD8,0xE0,0x46,
	0x80,0xE8,0xC0,0xEA,0xAB,0x40,0x3E,0xC8,0xA7,0x48,0xEE,0xF9,0xF1,0x0B,0x31,0x7C,
	0x7C,0x31,0x0B,0xF1,0xF9,0xEE,0x48,0xA7,0xC8,0x3E,0x40,0xAB,0xEA,0xC0,0xE8,0x80,
	0x46,0xE0,0xD8,0x9C,0xD1,0x19,0x14,0x6F,0xA6,0x3C,0x81,0x0F,0x6C,0xDF,0xA5,0x78,
	0x10,0x9D,0x0E,0x67,0xEC,0xEF,0xE7,0x28,0xB5,0xBE,0x5B,0x85,0x2D,0xF5,0x1D,0x62,
	0x27,0x08,0x97,0x71,0xB9,0xFA,0x39,0xC5,0x79,0xD9,0xB1,0xD3,0x6B,0x88,0x8F,0xB1,
	0xDB,0xB7,0x47,0x5C,0x50,0xBA,0xDD,0x56,0xAC,0xE5,0x98,0x82,0x69,0xD4,0xB8,0xFF,
	0xBF,0xA9,0x1A,0x12,0xCB,0xAD,0x8E,0x13,0xD2,0x60,0x61,0x7D,0xCF,0xC6,0xF3,0x3A,
	0x7E,0x2F,0xFB,0x8C,0xF0,0x51,0x11,0x3D,0xCC,0x25,0xAF,0x2A,0xF7,0x20,0xDA,0x09,
	0x6D,0x43,0x8A,0x26,0x92,0xA1,0x93,0x41,0xAA,0xE2,0x52,0xF6,0x4B,0x5F,0xD6,0xB2,
	0xB2,0xD6,0x5F,0x4B,0xF6,0x52,0xE2,0xAA,0x41,0x93,0xA1,0x92,0x26,0x8A,0x43,0x6D,
	0x09,0xDA,0x20,0xF7,0x2A,0xAF,0x25,0xCC,0x3D,0x11,0x51,0xF0,0x8C,0xFB,0x2F,0x7E,
	0x3A,0xF3,0xC6,0xCF,0x7D,0x61,0x60,0xD2,0x13,0x8E,0xAD,0xCB,0x12,0x1A,0xA9,0xBF,
	0xFF,0xB8,0xD4,0x69,0x82,0x98,0xE5,0xAC,0x56,0xDD,0xBA,0x50,0x5C,0x47,0xB7,0xDB ,
	0xAE,0x70,0x64,0x97,0xAD,0xFC,0x2B,0xD2,0xF4,0xA6,0x19,0x16,0x9A,0x8A,0xB2,0x05,
	0xAA,0x03,0x86,0xA1,0xD8,0x73,0xD7,0x78,0xEB,0x3A,0x1A,0xBB,0x42,0xFA,0x79,0x1B,
	0x57,0xCF,0xA9,0x2C,0x7F,0x39,0xD3,0x90,0xF6,0x76,0x49,0x93,0xE0,0x4D,0xD5,0x6C,
	0xE3,0x0F,0x14,0xAE,0x95,0x43,0x4B,0x33,0x6B,0x44,0x74,0x08,0x8E,0x5D,0x1C,0x7D,
	0xB3,0xFB,0x09,0x34,0x07,0xC8,0xEE,0x66,0xBA,0xE6,0xA2,0xAC,0x62,0x5E,0xA4,0x0E,
	0x23,0xEF,0xB5,0x8B,0x68,0xFF,0x47,0x55,0x0B,0xFE,0xE9,0x80,0xCC,0x8D,0x45,0x51,
	0x31,0x17,0x32,0xEA,0x2A,0x94,0xBD,0x11,0xDE,0xE7,0x85,0x96,0x9E,0x69,0xB7,0x77,
	0xDD,0x02,0xC9,0x82,0x2D,0x7B,0x7A,0x9D,0xFD,0x2F,0xF7,0x2E,0xA0,0xAB,0x48,0xC4,
	0xAE,0x70,0x64,0x97,0xAD,0xFC,0x2B,0xD2,0xF4,0xA6,0x19,0x16,0x9A,0x8A,0xB2,0x05,
	0xAA,0x03,0x86,0xA1,0xD8,0x73,0xD7,0x78,0xEB,0x3A,0x1A,0xBB,0x42,0xFA,0x79,0x1B,
	0x57,0xCF,0xA9,0x2C,0x7F,0x39,0xD3,0x90,0xF6,0x76,0x49,0x93,0xE0,0x4D,0xD5,0x6C,
	0xE3,0x0F,0x14,0xAE,0x95,0x43,0x4B,0x33,0x6B,0x44,0x74,0x08,0x8E,0x5D,0x1C,0x7D,
	0xB3,0xFB,0x09,0x34,0x07,0xC8,0xEE,0x66,0xBA,0xE6,0xA2,0xAC,0x62,0x5E,0xA4,0x0E,
	0x23,0xEF,0xB5,0x8B,0x68,0xFF,0x47,0x55,0x0B,0xFE,0xE9,0x80,0xCC,0x8D,0x45,0x51,
	0x31,0x17,0x32,0xEA,0x2A,0x94,0xBD,0x11,0xDE,0xE7,0x85,0x96,0x9E,0x69,0xB7,0x77,
	0xDD,0x02,0xC9,0x82,0x2D,0x7B,0x7A,0x9D,0xFD,0x2F,0xF7,0x2E,0xA0,0xAB,0x48,0xC4 ,
	0x6F,0xB1,0x9B,0x68,0x65,0x34,0x78,0x81,0x97,0xC5,0x5A,0x55,0xA3,0xB3,0xD8,0x6F,
	0x4B,0xE2,0x15,0x32,0xD0,0x7B,0xCF,0x60,0x43,0x92,0xB6,0x17,0xC2,0x7A,0xA9,0xCB,
	0x85,0x1D,0x99,0x1C,0x30,0x76,0xAB,0xE8,0xE7,0x67,0x87,0x5D,0xE4,0x49,0x48,0xF1,
	0xCC,0x20,0x4E,0xF4,0xCD,0x1B,0xAC,0xD4,0x51,0x7E,0x6A,0x16,0x91,0x42,0xBA,0xDB,
	0x71,0x39,0x02,0x3F,0xBD,0x72,0x9C,0x14,0x8F,0xD3,0xC9,0xC7,0x94,0xA8,0xA5,0x0F,
	0x6D,0xA1,0x66,0x58,0x23,0xB4,0xBF,0xAD,0x5F,0xAA,0x07,0x6E,0x8B,0xCA,0xC6,0xD2,
	0x28,0x0E,0xBB,0x63,0x9A,0x24,0xA7,0x0B,0x5B,0x62,0xEB,0xF8,0x05,0xF2,0x40,0x80,
	0xF0,0x2F,0x4D,0x06,0x74,0x22,0x50,0xB7,0x25,0xF7,0xD5,0x0C,0x44,0x4F,0xE5,0x69,
	0xB1,0x6F,0x68,0x9B,0x34,0x65,0x81,0x78,0xC5,0x97,0x55,0x5A,0xB3,0xA3,0x6F,0xD8,
	0xE2,0x4B,0x32,0x15,0x7B,0xD0,0x60,0xCF,0x92,0x43,0x17,0xB6,0x7A,0xC2,0xCB,0xA9,
	0x1D,0x85,0x1C,0x99,0x76,0x30,0xE8,0xAB,0x67,0xE7,0x5D,0x87,0x49,0xE4,0xF1,0x48,
	0x20,0xCC,0xF4,0x4E,0x1B,0xCD,0xD4,0xAC,0x7E,0x51,0x16,0x6A,0x42,0x91,0xDB,0xBA,
	0x39,0x71,0x3F,0x02,0x72,0xBD,0x14,0x9C,0xD3,0x8F,0xC7,0xC9,0xA8,0x94,0x0F,0xA5,
	0xA1,0x6D,0x58,0x66,0xB4,0x23,0xAD,0xBF,0xAA,0x5F,0x6E,0x07,0xCA,0x8B,0xD2,0xC6,
	0x0E,0x28,0x63,0xBB,0x24,0x9A,0x0B,0xA7,0x62,0x5B,0xF8,0xEB,0xF2,0x05,0x80,0x40,
	0x2F,0xF0,0x06,0x4D,0x22,0x74,0xB7,0x50,0xF7,0x25,0x0C,0xD5,0x4F,0x44,0x69,0xE5 ,
	0x70,0x90,0xBA,0x77,0xB6,0x7C,0x30,0x52,0x4E,0x3C,0xA3,0x8C,0xE7,0xA4,0xCF,0x2B,
	0x85,0x5E,0xA9,0xFC,0x6A,0xD1,0x65,0xDA,0x15,0xC0,0xE4,0x41,0x97,0x7F,0xAC,0x9E,
	0x8D,0xF7,0x73,0x14,0x12,0x63,0xBE,0xCA,0x98,0xC7,0x27,0x22,0x95,0xA1,0xA0,0x80,
	0x33,0xAA,0xC4,0x0B,0x56,0x3F,0x88,0x4F,0xF3,0xF8,0xEC,0xB4,0x45,0x2F,0xD7,0x0F,
	0x2C,0xAD,0x96,0x62,0xAF,0xA8,0x46,0x06,0x26,0x24,0x3E,0x6E,0xA2,0x69,0x64,0x39,
	0xE6,0xB7,0x70,0xD3,0xD6,0xF2,0xF9,0x58,0x3D,0x72,0xDF,0x0C,0x57,0xD2,0xDE,0x0E,
	0x48,0xFE,0x4B,0x03,0xCD,0xD9,0x5A,0x5C,0xC2,0x10,0x99,0x61,0x78,0xE3,0x51,0xFD,
	0xD8,0xAE,0xCC,0x2E,0xD0,0xF5,0x87,0x13,0x91,0xB9,0x9B,0xB8,0xAB,0xE9,0x43,0x86,
	0xBA,0x77,0x70,0x90,0x30,0x52,0xB6,0x7C,0xA3,0x8C,0x4E,0x3C,0xCF,0x2B,0xE7,0xA4,
	0xA9,0xFC,0x85,0x5E,0x65,0xDA,0x6A,0xD1,0xE4,0x41,0x15,0xC0,0xAC,0x9E,0x97,0x7F,
	0x73,0x14,0x8D,0xF7,0xBE,0xCA,0x12,0x63,0x27,0x22,0x98,0xC7,0xA0,0x80,0x95,0xA1,
	0xC4,0x0B,0x33,0xAA,0x88,0x4F,0x56,0x3F,0xEC,0xB4,0xF3,0xF8,0xD7,0x0F,0x45,0x2F,
	0x96,0x62,0x2C,0xAD,0x46,0x06,0xAF,0xA8,0x3E,0x6E,0x26,0x24,0x64,0x39,0xA2,0x69,
	0x70,0xD3,0xE6,0xB7,0xF9,0x58,0xD6,0xF2,0xDF,0x0C,0x3D,0x72,0xDE,0x0E,0x57,0xD2,
	0x4B,0x03,0x48,0xFE,0x5A,0x5C,0xCD,0xD9,0x99,0x61,0xC2,0x10,0x51,0xFD,0x78,0xE3,
	0xCC,0x2E,0xD8,0xAE,0x87,0x13,0xD0,0xF5,0x9B,0xB8,0x91,0xB9,0x43,0x86,0xAB,0xE9 ,
	0x8F,0x6F,0x7B,0xB6,0xE5,0x2F,0xF8,0x9A,0x0D,0x7F,0xC0,0xEF,0x8D,0xCE,0xF6,0x12,
	0x16,0xCD,0x48,0x1D,0x72,0xC9,0x6D,0xD2,0xB9,0x6C,0x4C,0xE9,0x47,0xAF,0x2C,0x1E,
	0xBD,0xC7,0xA1,0xC6,0x6A,0x1B,0xF1,0x85,0x56,0x09,0x36,0x33,0x08,0x3C,0xA4,0x84,
	0x69,0xF0,0xEB,0x24,0xB1,0xD8,0xD0,0x17,0xED,0xE6,0xD6,0x8E,0xE3,0x89,0xC8,0x10,
	0x27,0xA6,0x54,0xA0,0xDD,0xDA,0xFC,0xBC,0x4D,0x4F,0x0B,0x5B,0xA3,0x68,0x92,0xCF,
	0x35,0x64,0x3E,0x9D,0x2E,0x0A,0xB2,0x13,0xD3,0x9C,0x8B,0x58,0xD4,0x51,0x99,0x49,
	0xC1,0x77,0x52,0x1A,0xD7,0xC3,0xEA,0xEC,0xAC,0x7E,0x1C,0xE4,0x8F,0x14,0xCA,0x66,
	0x5C,0x2A,0xE1,0x03,0xFA,0xDF,0xDE,0x4A,0xB3,0x9B,0x43,0x60,0x06,0x44,0xA7,0x62,
	0xB6,0x7B,0x6F,0x8F,0x9A,0xF8,0x2F,0xE5,0xEF,0xC0,0x7F,0x0D,0x12,0xF6,0xCE,0x8D,
	0x1D,0x48,0xCD,0x16,0xD2,0x6D,0xC9,0x72,0xE9,0x4C,0x6C,0xB9,0x1E,0x2C,0xAF,0x47,
	0xC6,0xA1,0xC7,0xBD,0x85,0xF1,0x1B,0x6A,0x33,0x36,0x09,0x56,0x84,0xA4,0x3C,0x08,
	0x24,0xEB,0xF0,0x69,0x17,0xD0,0xD8,0xB1,0x8E,0xD6,0xE6,0xED,0x10,0xC8,0x89,0xE3,
	0xA0,0x54,0xA6,0x27,0xBC,0xFC,0xDA,0xDD,0x5B,0x0B,0x4F,0x4D,0xCF,0x92,0x68,0xA3,
	0x9D,0x3E,0x64,0x35,0x13,0xB2,0x0A,0x2E,0x58,0x8B,0x9C,0xD3,0x49,0x99,0x51,0xD4,
	0x1A,0x52,0x77,0xC1,0xEC,0xEA,0xC3,0xD7,0xE4,0x1C,0x7E,0xAC,0x66,0xCA,0x14,0x8F,
	0x03,0xE1,0x2A,0x5C,0x4A,0xDE,0xDF,0xFA,0x60,0x43,0x9B,0xB3,0x62,0xA7,0x44,0x06 ,
	0x3C,0xEB,0x33,0x6C,0x3F,0x67,0x7C,0x29,0x54,0x5C,0x7E,0x58,0x3A,0x70,0xD5,0x4B,
	0xE8,0xA8,0x59,0xF5,0x9A,0xD8,0x08,0x2C,0x73,0x8A,0xA9,0x74,0xDA,0x4A,0xCA,0xD4,
	0xFE,0xFB,0xB7,0x7A,0xD6,0x0D,0xCD,0xC6,0xA5,0x30,0x01,0x88,0xB3,0x0B,0x9D,0x77,
	0x89,0x12,0x6D,0x6A,0xFF,0x5E,0x32,0xF7,0x62,0x68,0x2E,0xEA,0x87,0x71,0x46,0x9F,
	0x15,0x25,0x98,0xDC,0xA1,0x16,0x7F,0x8E,0x19,0x86,0x5D,0x39,0xC1,0x3E,0x5B,0x9B,
	0x1B,0xD2,0xF6,0xE3,0x50,0xC2,0x04,0x3D,0xEC,0x0A,0xA3,0xA7,0x2B,0x79,0x0F,0x76,
	0xB9,0x36,0x24,0x6F,0xA2,0xB5,0xAB,0x94,0x8B,0xAC,0x2A,0xA0,0xCB,0x22,0x18,0x41,
	0xEE,0x45,0x02,0xE7,0x1E,0x3C,0xB1,0xF8,0x0C,0xE2,0x61,0x37,0x51,0x66,0xDE,0xDD,
	0x3F,0x67,0x7C,0x29,0x3C,0xEB,0x33,0x6C,0x3A,0x70,0xD5,0x4B,0x54,0x5C,0x7E,0x58,
	0x9A,0xD8,0x08,0x2C,0xE8,0xA8,0x59,0xF5,0xDA,0x4A,0xCA,0xD4,0x73,0x8A,0xA9,0x74,
	0xD6,0x0D,0xCD,0xC6,0xFE,0xFB,0xB7,0x7A,0xB3,0x0B,0x9D,0x77,0xA5,0x30,0x01,0x88,
	0xFF,0x5E,0x32,0xF7,0x89,0x12,0x6D,0x6A,0x87,0x71,0x46,0x9F,0x62,0x68,0x2E,0xEA,
	0xA1,0x16,0x7F,0x8E,0x15,0x25,0x98,0xDC,0xC1,0x3E,0x5B,0x9B,0x19,0x86,0x5D,0x39,
	0x50,0xC2,0x04,0x3D,0x1B,0xD2,0xF6,0xE3,0x2B,0x79,0x0F,0x76,0xEC,0x0A,0xA3,0xA7,
	0xA2,0xB5,0xAB,0x94,0xB9,0x36,0x24,0x6F,0xCB,0x22,0x18,0x41,0x8B,0xAC,0x2A,0xA0,
	0x1E,0x3C,0xB1,0xF8,0xEE,0x45,0x02,0xE7,0x51,0x66,0xDE,0xDD,0x0C,0xE2,0x61,0x37 ,
	0xF4,0x23,0x60,0x3F,0xFE,0xA6,0x83,0xD6,0x6D,0x65,0x14,0x32,0x59,0x13,0x96,0x08,
	0xE0,0xA0,0x41,0xED,0x7B,0x39,0x9B,0xBF,0xF3,0x0A,0x79,0xA4,0x72,0xE2,0x66,0x78,
	0xB1,0xB4,0xCF,0x02,0x04,0xDF,0xFD,0xF6,0xA1,0x34,0x9C,0x15,0xA2,0x1A,0x53,0xB9,
	0xD1,0x4A,0x8A,0x8D,0xD0,0x71,0x68,0xAD,0x7D,0x77,0x88,0x4C,0xBD,0x4B,0x58,0x81,
	0xAF,0x9F,0xEA,0xAE,0x63,0xD4,0x74,0x85,0xEF,0x70,0x5C,0x38,0xF4,0x0B,0x30,0xF0,
	0x50,0x99,0x0E,0x1B,0x1E,0x8C,0xD7,0xEE,0xAB,0x4D,0x20,0x24,0x7F,0x2D,0xE1,0x98,
	0x09,0x86,0x3E,0x75,0xBB,0xAC,0x22,0x1D,0x10,0x37,0xDD,0x57,0x4E,0xA7,0x76,0x2F,
	0xB7,0x1C,0x28,0xCD,0x33,0x11,0x35,0x7C,0xE8,0x06,0xCC,0x9A,0x89,0xBE,0xFC,0xFF,
	0xA6,0xFE,0xD6,0x83,0x23,0xF4,0x3F,0x60,0x13,0x59,0x08,0x96,0x65,0x6D,0x32,0x14,
	0x39,0x7B,0xBF,0x9B,0xA0,0xE0,0xED,0x41,0xE2,0x72,0x78,0x66,0x0A,0xF3,0xA4,0x79,
	0xDF,0x04,0xF6,0xFD,0xB4,0xB1,0x02,0xCF,0x1A,0xA2,0xB9,0x53,0x34,0xA1,0x15,0x9C,
	0x71,0xD0,0xAD,0x68,0x4A,0xD1,0x8D,0x8A,0x4B,0xBD,0x81,0x58,0x77,0x7D,0x4C,0x88,
	0xD4,0x63,0x85,0x74,0x9F,0xAF,0xAE,0xEA,0x0B,0xF4,0xF0,0x30,0x70,0xEF,0x38,0x5C,
	0x8C,0x1E,0xEE,0xD7,0x99,0x50,0x1B,0x0E,0x2D,0x7F,0x98,0xE1,0x4D,0xAB,0x24,0x20,
	0xAC,0xBB,0x1D,0x22,0x86,0x09,0x75,0x3E,0xA7,0x4E,0x2F,0x76,0x37,0x10,0x57,0xDD,
	0x11,0x33,0x7C,0x35,0x1C,0xB7,0xCD,0x28,0xBE,0x89,0xFF,0xFC,0x06,0xE8,0x9A,0xCC ,
	0x27,0x6B,0x28,0xEC,0xE1,0x87,0xA2,0xC9,0x29,0x72,0x03,0x76,0x80,0xEA,0x6F,0xD1,
	0x5A,0x0A,0xEB,0x57,0xB5,0x85,0x27,0x71,0xA6,0x0F,0x7C,0xF1,0x24,0xB0,0x34,0x2E,
	0x93,0xA1,0xDA,0x20,0x0C,0x35,0x17,0xFE,0xD0,0xDC,0x74,0x64,0xDD,0xBA,0xF3,0xC6,
	0x4A,0x6E,0xAE,0x16,0x2F,0xFB,0xE2,0x52,0xA9,0x1A,0xE5,0x98,0x1F,0xCD,0xDE,0x23,
	0xBD,0x45,0x30,0xBC,0x3E,0x40,0xE0,0xD8,0xD9,0xB1,0x9D,0x0E,0x5D,0xFC,0xC7,0x59,
	0xA5,0xDF,0x48,0xEE,0x95,0x9A,0xC1,0x65,0x77,0x55,0x38,0xF8,0x1D,0xF5,0x39,0xFA,
	0x5E,0x7B,0xC3,0x22,0xDB,0x5C,0xD2,0x7D,0x6D,0x26,0xCC,0x2A,0xD7,0xD5,0x04,0xB6,
	0x13,0xCB,0xFF,0x69,0x1B,0x90,0xB4,0x54,0x07,0xA0,0x6A,0x75,0x3D,0xF0,0xB2,0x4B,
	0xA2,0xC9,0xE1,0x87,0x28,0xEC,0x27,0x6B,0x6F,0xD1,0x80,0xEA,0x03,0x76,0x29,0x72,
	0x27,0x71,0xB5,0x85,0xEB,0x57,0x5A,0x0A,0x34,0x2E,0x24,0xB0,0x7C,0xF1,0xA6,0x0F,
	0x17,0xFE,0x0C,0x35,0xDA,0x20,0x93,0xA1,0xF3,0xC6,0xDD,0xBA,0x74,0x64,0xD0,0xDC,
	0xE2,0x52,0x2F,0xFB,0xAE,0x16,0x4A,0x6E,0xDE,0x23,0x1F,0xCD,0xE5,0x98,0xA9,0x1A,
	0xE0,0xD8,0x3E,0x40,0x30,0xBC,0xBD,0x45,0xC7,0x59,0x5D,0xFC,0x9D,0x0E,0xD9,0xB1,
	0xC1,0x65,0x95,0x9A,0x48,0xEE,0xA5,0xDF,0x39,0xFA,0x1D,0xF5,0x38,0xF8,0x77,0x55,
	0xD2,0x7D,0xDB,0x5C,0xC3,0x22,0x5E,0x7B,0x04,0xB6,0xD7,0xD5,0xCC,0x2A,0x6D,0x26,
	0xB4,0x54,0x1B,0x90,0xFF,0x69,0x13,0xCB,0xB2,0x4B,0x3D,0xF0,0x6A,0x75,0x07,0xA0 ,
	0x74,0x38,0xE0,0x24,0x1E,0x78,0x63,0x08,0x43,0x18,0x3A,0x4F,0xC3,0xA9,0x0C,0xB2,
	0x42,0x12,0xE3,0x5F,0x26,0x16,0xC6,0x90,0x76,0xDF,0xFC,0x71,0x88,0x1C,0x9C,0x86,
	0xEB,0xD9,0x95,0x6F,0x3C,0x05,0xC5,0x2C,0x4D,0x41,0x70,0x60,0x13,0x74,0xE2,0xD7,
	0xAD,0x89,0xF6,0x4E,0x75,0xA1,0xCD,0x7D,0x0F,0xBC,0xFA,0x87,0x01,0xD3,0xE4,0x19,
	0xCF,0x37,0x8A,0x06,0x35,0x4B,0x22,0x1A,0xD8,0xB0,0x6B,0xF8,0x36,0x97,0xF2,0x6C,
	0x5D,0x27,0x03,0xA5,0x46,0x49,0x8F,0x2B,0xF4,0xD6,0x7F,0xBF,0xF3,0x1B,0x6D,0xAE,
	0x44,0x61,0x73,0x92,0x52,0xD5,0xCB,0x64,0x9A,0xD1,0x57,0xB1,0xB9,0xBB,0x81,0x33,
	0x39,0xE1,0xA6,0x30,0x9F,0x14,0x99,0x79,0xAA,0x0D,0x8E,0x91,0x1F,0xD2,0x6A,0x93,
	0x08,0x63,0x78,0x1E,0x24,0xE0,0x38,0x74,0xB2,0x0C,0xA9,0xC3,0x4F,0x3A,0x18,0x43,
	0x90,0xC6,0x16,0x26,0x5F,0xE3,0x12,0x42,0x86,0x9C,0x1C,0x88,0x71,0xFC,0xDF,0x76,
	0x2C,0xC5,0x05,0x3C,0x6F,0x95,0xD9,0xEB,0xD7,0xE2,0x74,0x13,0x60,0x70,0x41,0x4D,
	0x7D,0xCD,0xA1,0x75,0x4E,0xF6,0x89,0xAD,0x19,0xE4,0xD3,0x01,0x87,0xFA,0xBC,0x0F,
	0x1A,0x22,0x4B,0x35,0x06,0x8A,0x37,0xCF,0x6C,0xF2,0x97,0x36,0xF8,0x6B,0xB0,0xD8,
	0x2B,0x8F,0x49,0x46,0xA5,0x03,0x27,0x5D,0xAE,0x6D,0x1B,0xF3,0xBF,0x7F,0xD6,0xF4,
	0x64,0xCB,0xD5,0x52,0x92,0x73,0x61,0x44,0x33,0x81,0xBB,0xB9,0xB1,0x57,0xD1,0x9A,
	0x79,0x99,0x14,0x9F,0x30,0xA6,0xE1,0x39,0x93,0x6A,0xD2,0x1F,0x91,0x8E,0x0D,0xAA };

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


// This function adds the round key to state.
// The round key is added to the state by an XOR function.
static void AddRoundKey(uint8_t round, state_t* state, const uint8_t* RoundKey)
{
	uint8_t i, j;
	for (i = 0; i < 4; ++i)
	{
		for (j = 0; j < 4; ++j)
		{
			(*state)[i][j] ^= RoundKey[(round * Nb * 4) + (i * Nb) + j];
		}
	}
}

// The SubBytes Function Substitutes the values in the
// state matrix with values in an S-box.
static void SubBytes(state_t* state)
{
	uint8_t i, j;
	for (i = 0; i < 4; ++i)
	{
		for (j = 0; j < 4; ++j)
		{
			(*state)[j][i] = getSBoxValue((*state)[j][i]);
		}
	}
}

static void SubBytes1(state_t* state, uint8_t round)
{
	uint8_t r = round - 1;
	(*state)[0][0] = sbox1[((*state)[0][0] + 256*r) % 4096];
	(*state)[0][1] = sbox1[((*state)[0][1] + 256*r + 256*1) % 4096];
	(*state)[0][2] = sbox1[((*state)[0][2] + 256*r + 256*2) % 4096];
	(*state)[0][3] = sbox1[((*state)[0][3] + 256*r + 256*3) % 4096];
	(*state)[1][0] = sbox1[((*state)[1][0] + 256*r + 256*4) % 4096];
	(*state)[1][1] = sbox1[((*state)[1][1] + 256*r + 256*5) % 4096];
	(*state)[1][2] = sbox1[((*state)[1][2] + 256*r + 256*6) % 4096];
	(*state)[1][3] = sbox1[((*state)[1][3] + 256*r + 256*7) % 4096];
	(*state)[2][0] = sbox1[((*state)[2][0] + 256*r + 256*8) % 4096];
	(*state)[2][1] = sbox1[((*state)[2][1] + 256*r + 256*9) % 4096];
	(*state)[2][2] = sbox1[((*state)[2][2] + 256*r + 256*10) % 4096];
	(*state)[2][3] = sbox1[((*state)[2][3] + 256*r + 256*11) % 4096];
	(*state)[3][0] = sbox1[((*state)[3][0] + 256*r + 256*12) % 4096];
	(*state)[3][1] = sbox1[((*state)[3][1] + 256*r + 256*13) % 4096];
	(*state)[3][2] = sbox1[((*state)[3][2] + 256*r + 256*14) % 4096];
	(*state)[3][3] = sbox1[((*state)[3][3] + 256*r + 256*15) % 4096];
}

// The ShiftRows() function shifts the rows in the state to the left.
// Each row is shifted with different offset.
// Offset = Row number. So the first row is not shifted.
static void ShiftRows(state_t* state)
{
	uint8_t temp;

	// Rotate first row 1 columns to left  
	temp = (*state)[0][1];
	(*state)[0][1] = (*state)[1][1];
	(*state)[1][1] = (*state)[2][1];
	(*state)[2][1] = (*state)[3][1];
	(*state)[3][1] = temp;

	// Rotate second row 2 columns to left  
	temp = (*state)[0][2];
	(*state)[0][2] = (*state)[2][2];
	(*state)[2][2] = temp;

	temp = (*state)[1][2];
	(*state)[1][2] = (*state)[3][2];
	(*state)[3][2] = temp;

	// Rotate third row 3 columns to left
	temp = (*state)[0][3];
	(*state)[0][3] = (*state)[3][3];
	(*state)[3][3] = (*state)[2][3];
	(*state)[2][3] = (*state)[1][3];
	(*state)[1][3] = temp;
}

static uint8_t xtime(uint8_t x)
{
	uint8_t res;
	res = x << 1;
	if (((x >> 7) & 1) != 0)
		res = res ^ 0x1b;
	return res;
}

// MixColumns function mixes the columns of the state matrix
static void MixColumns(state_t* state, uint8_t round)
{
	uint8_t i;
	uint8_t Tmp, Tm, t;
	uint8_t a = 0;
	for (i = 0; i < 4; ++i)
	{
		t = (*state)[i][0];
		Tmp = (*state)[i][0] ^ (*state)[i][1] ^ (*state)[i][2] ^ (*state)[i][3];
		Tm = (*state)[i][0] ^ (*state)[i][1]; Tm = xtime(Tm);  (*state)[i][0] ^= Tm ^ Tmp;
		Tm = (*state)[i][1] ^ (*state)[i][2]; Tm = xtime(Tm);  (*state)[i][1] ^= Tm ^ Tmp;
		Tm = (*state)[i][2] ^ (*state)[i][3]; Tm = xtime(Tm);  (*state)[i][2] ^= Tm ^ Tmp;
		Tm = (*state)[i][3] ^ t;              Tm = xtime(Tm);  (*state)[i][3] ^= Tm ^ Tmp;
	}
}


// Cipher is the main function that encrypts the PlainText.
static void Cipher(state_t* state, const uint8_t* RoundKey)
{
	uint8_t round = 0;
	uint8_t state2[4][4] = { {0x00, 0x01, 0x00, 0x01}, {0x01, 0xa1, 0x98, 0xaf}, {0xda, 0x78, 0x17, 0x34}, {0x86, 0x15, 0x35, 0x66} };
	uint8_t state3[4][4] = { {0x00, 0x01, 0x00, 0x01}, {0x01, 0xa1, 0x98, 0xaf}, {0xda, 0x78, 0x17, 0x34}, {0x86, 0x15, 0x35, 0x66} };
	uint8_t rk[4][4] = { {0x78, 0x79, 0x7a, 0x7b}, {0x7c, 0x7d, 0x7e, 0x7f}, {0x80, 0x81, 0x82, 0x83}, {0x84, 0x85, 0x86, 0x87} };
	uint8_t tmp = 0;

	// Add the First round key to the state before starting the rounds.
	AddRoundKey(0, state, RoundKey);

	// There will be Nr rounds.
	// The first Nr-1 rounds are identical.
	// These Nr rounds are executed in the loop below.
	// Last one without MixColumns()
	for (round = 1; round <= Nr ; ++round)
	{
		for (int i = 0; i < 4; i++) {
			for (int j = 0; j < 4; j++) {
				state2[i][j] = (*state)[i][j];
			}
		}
		SubBytes(state);
		ShiftRows(state);
		if (round != Nr) {
			MixColumns(state, round);
			AddRoundKey(round, state, RoundKey);
		}

		SubBytes1((state_t*)state2,round);
		ShiftRows((state_t*)state2);

		if (round != Nr) {
			MixColumns((state_t*)state2, round);
			tmp = rk[0][0];		rk[0][0]=rk[0][1]; 	rk[0][1]=rk[0][2]; 	rk[0][2]=rk[0][3];
			rk[0][3]=rk[1][0];	rk[1][0]=rk[1][1];	rk[1][1]=rk[1][2];	rk[1][2]=rk[1][3];
			rk[1][3]=rk[2][0];	rk[2][0]=rk[2][1];	rk[2][1]=rk[2][2];	rk[2][2]=rk[2][3];
			rk[2][3]=rk[3][0];	rk[3][0]=rk[3][1];	rk[3][1]=rk[3][2];	rk[3][2]=rk[3][3];
			rk[3][3]=tmp;
			for (int i = 0; i < 4; i++) {
				for (int j = 0; j < 4; j++) {
					state2[i][j] ^= rk[i][j];
				}
			}
			for (int i = 0; i < 4; i++) {
				for (int j = 0; j < 4; j++) {
					(*state)[i][j] ^= state2[i][j];
				}
			}
		}
	}


	// Add round key to last round
	AddRoundKey(Nr, state, RoundKey);
	for (int i = 0; i < 4; i++) {
		for (int j = 0; j < 4; j++) {
			(*state)[i][j] ^= state2[i][j];
		}
	}
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
    AES_init_ctx(&ctx, ekey);   
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
	trigger_high();
	for (uint8_t i = 0; i < 16; i++)
	{
		ptx[i] ^= rkx[i];
	}
    	AES_ECB_encrypt(&ctx, ptx);
	trigger_low();
    	simpleserial_put('r', 16, ptx);
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
