/******************************************************************************
 Copyright (c) 1998-2008, Brian Gladman, Worcester, UK. All rights reserved.

 LICENSE TERMS

 The redistribution and use of this software (with or without changes)
 is allowed without the payment of fees or royalties provided that:

  1. source code distributions include the above copyright notice, this
     list of conditions and the following disclaimer;

  2. binary distributions include the above copyright notice, this list
     of conditions and the following disclaimer in their documentation;

  3. the name of the copyright holder is not used to endorse products
     built using this software without specific written permission.

 DISCLAIMER

 This software is provided 'as is' with no explicit or implied warranties
 in respect of its properties, including, but not limited to, correctness
 and/or fitness for purpose.
 ---------------------------------------------------------------------------
 Issue 09/09/2006

 This is an AES implementation that uses only 8-bit byte operations on the
 cipher state (there are options to use 32-bit types if available).

 The combination of mix columns and byte substitution used here is based on
 that developed by Karl Malbrain. His contribution is acknowledged.
 ******************************************************************************/

/******************************************************************************
   This version derived by Mark Tillotson 2012-01-23, tidied up, slimmed down
   and tailored to 8-bit microcontroller abilities and Arduino datatypes.

   The s-box and inverse s-box were retained as tables (0.5kB PROGMEM) but all
   the other transformations are coded to save table space.  Many efficiency
   improvments to the routines mix_sub_columns() and inv_mix_sub_columns()
   (mainly common sub-expression elimination).

   Only the routines with precalculated subkey schedule are retained (together
   with set_key() - this does however mean each AES object takes 240 bytes of
   RAM, alas)

   The CBC routines side-effect the iv argument (so that successive calls work
   together correctly).

   All the encryption and decryption routines work with plain == cipher for
   in-place encryption, note.
 ******************************************************************************/
/* functions for finite field multiplication in the AES Galois field    */

/* code was modified by george spanos <spaniakos@gmail.com>
 * 16/12/14
 * code was modified by jose nogueira <josenogueira@gmail.com.com
 * 08/03/19
 */

/******************************************************************************
 * Include Files                                                              *
 ******************************************************************************/
#include <stdlib.h>

#include "AES.h"



/******************************************************************************
 * Defines and Macros                                                         *
 ******************************************************************************/
#define WPOLY   0x011B
#define DPOLY   0x008D

#define f2(x)   ((x) & 0x80           ? (x << 1) ^ WPOLY : x << 1)
#define d2(x)  (((x) >> 1) ^ ((x) & 1 ?            DPOLY : 0))


/******************************************************************************
 * Global Variables Files                                                     *
 ******************************************************************************/
AES_t mAes = { 0 };

static const uint8_t mAES_s_fwd[0x100] PROGMEM =
{
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
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
};

static const uint8_t mAES_s_inv[0x100] PROGMEM =
{
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d,
};


/******************************************************************************
 * Internal function declaration                                              *
 ******************************************************************************/
uint8_t  mAES_IvPadding(          void);
uint8_t  mAES_s_box(              const uint8_t x);
uint8_t  mAES_is_box(             const uint8_t x);
void     mAES_xor_block(          uint8_t*      d    , uint8_t* s);
void     mAES_copy_and_key(       uint8_t*      d    , uint8_t* s, uint8_t* k);
void     mAES_shift_sub_rows(     uint8_t*      st   );
void     mAES_inv_shift_sub_rows( uint8_t*      st   );
void     mAES_mix_sub_columns(    uint8_t*      dt   , uint8_t* st);
void     mAES_inv_mix_sub_columns(uint8_t*      dt   , uint8_t* st);
uint8_t  mAES_EncryptBlock(       uint8_t*      block);
uint8_t  mAES_DecryptBlock(       uint8_t*      cipher, uint8_t* data);
uint8_t  mAES_EncryptCBC(         uint8_t*      data       ,
                                  uint8_t*      cipher     ,
                                  const uint8_t blocks     );
uint8_t  mAES_DecryptCBC(         uint8_t*      cipher     ,
                                  uint8_t*      data       ,
                                  const uint8_t blocks     );


/******************************************************************************
 * Functions                                                                  *
 ******************************************************************************/


/**
 *
 */
void AES_Init(void)
{
    uint8_t  key[KEY_SCHEDULE_BYTES];
    memcpy_P(key, PSTR("ThisIsAKey"), 16);

    AES_KeySet(key, 128);
}


/**
 *
 */
uint8_t AES_IvSize(void)
{
    return mAes.Iv.Length;
}

/**
 *
 */
void AES_IvGet(uint8_t* iv)
{
    memcpy(iv, mAes.Iv.Data, mAes.Iv.Length);
}


/**
 *
 */
uint8_t  AES_IvSet(uint8_t* iv, const uint8_t size)
{
    switch (size)
    {
        case   4 :
        case  32 : mAes.Iv.Length =  4; break;

        case   8 :
        case  64 : mAes.Iv.Length =  8; break;

        case  16 :
        case 128 : mAes.Iv.Length = 16; break;

        default  : mAes.Iv.Length =  0; break;
    }

    memcpy(mAes.Iv.Data, iv, mAes.Iv.Length);

    return mAES_IvPadding();
}


/**
 *
 */
uint8_t  AES_IvRandomize(const uint8_t size)
{
    switch (size)
    {
        case   4 :
        case  32 : mAes.Iv.Length =  4; break;

        case   8 :
        case  64 : mAes.Iv.Length =  8; break;

        case  16 :
        case 128 : mAes.Iv.Length = 16; break;

        default  : mAes.Iv.Length = 16; break;
    }

    for (uint8_t index = 0; index < mAes.Iv.Length; ++index)
    {
        mAes.Iv.Data[index] = rand() & 0xFF;
    }

    // Perform IV padding (by replication)
    return mAES_IvPadding();
}


/**
 *
 */
uint8_t  AES_KeySet(uint8_t* key, uint16_t keylen)
{
    switch (keylen)
    {
        case 16:
        case 128:
        {
            keylen     = 16; // 10 rounds
            mAes.Round = 10;
            break;
        }

        case 24:
        case 192:
        {
            keylen     = 24; // 12 rounds
            mAes.Round = 12;
            break;
        }

        case 32:
        case 256:
        {
            keylen     = 32; // 14 rounds
            mAes.Round = 14;
            break;
        }

        default:
        {
            mAes.Round = 0;
            return ERROR;
        }
    }

    const uint8_t hi = (mAes.Round + 1) << 4 ;

    // Copy key
    memcpy(mAes.Key, key, keylen);

    uint8_t t[4];
    uint8_t next = keylen;

    for (uint8_t cc = keylen, rc = 1; cc < hi ; cc += N_COL)
    {
        for (uint8_t i = 0 ; i < N_COL ; ++i)
        {
            t[i] = mAes.Key[cc - 4 + i];
        }

        if (cc == next)
        {
            next        += keylen;
            uint8_t ttt  = t[0];
            t[0]         = mAES_s_box(t[1]) ^ rc;
            t[1]         = mAES_s_box(t[2]);
            t[2]         = mAES_s_box(t[3]);
            t[3]         = mAES_s_box(ttt);
            rc           = f2(rc);
        }
        else if (keylen == 32 && (cc & 31) == 16)
        {
            for (uint8_t i = 0 ; i < 4 ; ++i)
            {
                t[i] = mAES_s_box(t[i]);
            }
        }

        uint8_t tt = cc - keylen;

        for (uint8_t i = 0 ; i < N_COL ; ++i)
        {
            mAes.Key[cc + i] = mAes.Key[tt + i] ^ t[i];
        }
    }

    return SUCCESS ;
}


/**
 *
 */
uint8_t AES_SizeAfterPadding(const uint8_t size)
{
    const uint8_t pad = N_BLOCK - (size % N_BLOCK);

    return (size + pad);
}


/**
 *
 */
uint8_t AES_Padding(uint8_t* data, const uint8_t size, uint8_t* padded)
{
    const uint8_t size_padded = AES_SizeAfterPadding(size);

    if (size_padded >= AES_BUFFER_SIZE) return 0;

    // Copy complete contents
    if (data != padded) memcpy(padded, data, size);

    // Pad the rest
    for (uint8_t index = size; index < size_padded; ++index)
    {
        // Pad with zeros
        padded[index] = '\0';
    }

    return size_padded;
}



/**
 *
 */
uint8_t  AES_Encrypt(uint8_t* text, const uint8_t size, uint8_t* ciphertext)
{
    // Pad input data and move it to internal buffer
    const uint8_t size_padded = AES_Padding(text, size, mAes.Buffer.Data);

    // Calculate number of blocks
    const uint8_t blocks = size_padded / N_BLOCK;

    return mAES_EncryptCBC(mAes.Buffer.Data, ciphertext, blocks);
}


/**
 *
 */
uint8_t  AES_Decrypt(uint8_t* ciphertext, const uint8_t size, uint8_t* text)
{
    // Copy input data to internal buffer
    memcpy(mAes.Buffer.Data, ciphertext, size);

    // Calcualte number of blocks
    const uint8_t blocks = size / N_BLOCK;

    // Decrypt
    return mAES_DecryptCBC(mAes.Buffer.Data, text, blocks);
}


/******************************************************************************
 * Internal Functions                                                         *
 ******************************************************************************/


/**
 *
 */
uint8_t  mAES_IvPadding(void)
{
    uint8_t size = mAes.Iv.Length;

    if (size == 0) return ERROR;

    // Perform IV padding (by replication)
    while (size < 16)
    {
        memcpy(mAes.Iv.Data + size, mAes.Iv.Data, size);
        size *= 2;
    }

    return SUCCESS;
}


/**
 *
 */
uint8_t mAES_s_box(const uint8_t x)
{
    return pgm_read_byte(&mAES_s_fwd[x]);
}


/**
 * @brief Inverse Sbox
 */
uint8_t mAES_is_box(const uint8_t x)
{
    return pgm_read_byte(&mAES_s_inv[x]);
}


/**
 *
 */
void mAES_xor_block(uint8_t* d, uint8_t* s)
{
    for (uint8_t index = 0 ; index < N_BLOCK ; index += 4)
    {
        // For loop unrolling
        *d++ ^= *s++;
        *d++ ^= *s++;
        *d++ ^= *s++;
        *d++ ^= *s++;
    }
}


/**
 *
 */
void mAES_copy_and_key(uint8_t* d, uint8_t* s, uint8_t* k)
{
    for (uint8_t index = 0; index < N_BLOCK ; index += 4)
    {
        // For loop unrolling
        *d++ = *s++ ^ *k++;
        *d++ = *s++ ^ *k++;
        *d++ = *s++ ^ *k++;
        *d++ = *s++ ^ *k++;
    }
}


/**
 *
 */
void mAES_shift_sub_rows(uint8_t* st)
{
    st[ 0]     = mAES_s_box(st[ 0]);
    st[ 4]     = mAES_s_box(st[ 4]);
    st[ 8]     = mAES_s_box(st[ 8]);
    st[12]     = mAES_s_box(st[12]);

    uint8_t tt = st[1];
    st[ 1]     = mAES_s_box(st[ 5]);
    st[ 5]     = mAES_s_box(st[ 9]);
    st[ 9]     = mAES_s_box(st[13]);
    st[13]     = mAES_s_box(tt);

    tt         = st[2];
    st[ 2]     = mAES_s_box(st[10]);
    st[10]     = mAES_s_box(tt);
    tt         = st[6];
    st[ 6]     = mAES_s_box(st[14]);
    st[14]     = mAES_s_box(tt);

    tt         = st[15] ;
    st[15]     = mAES_s_box(st[11]);
    st[11]     = mAES_s_box(st[ 7]);
    st[ 7]     = mAES_s_box(st[ 3]);
    st[ 3]     = mAES_s_box(tt);
}


/**
 *
 */
void mAES_inv_shift_sub_rows(uint8_t* st)
{
  st[ 0]  = mAES_is_box(st[ 0]);
  st[ 4]  = mAES_is_box(st[ 4]);
  st[ 8]  = mAES_is_box(st[ 8]);
  st[12]  = mAES_is_box(st[12]);

  uint8_t tt = st[13] ;
  st[13]  = mAES_is_box(st[ 9]);
  st[9]   = mAES_is_box(st[ 5]);
  st[5]   = mAES_is_box(st[ 1]);
  st[1]   = mAES_is_box(tt);

  tt      = st[2];
  st[ 2]  = mAES_is_box(st[10]);
  st[10]  = mAES_is_box(tt);
  tt      = st[6];
  st[ 6]  = mAES_is_box(st[14]);
  st[14]  = mAES_is_box(tt);

  tt      = st[3] ;
  st[3]   = mAES_is_box(st[ 7]);
  st[7]   = mAES_is_box(st[11]);
  st[11]  = mAES_is_box(st[15]);
  st[15]  = mAES_is_box(tt);
}


/**
 *
 */
void mAES_mix_sub_columns(uint8_t* dt, uint8_t* st)
{
    uint8_t j = 5;
    uint8_t k = 10;
    uint8_t l = 15;

    for (uint8_t i = 0 ; i < N_BLOCK ; i += N_COL)
    {
        const uint8_t a = st[i];
        const uint8_t b = st[j];  j = (j + N_COL) & 0x0F;
        const uint8_t c = st[k];  k = (k + N_COL) & 0x0F;
        const uint8_t d = st[l];  l = (l + N_COL) & 0x0F;

        const uint8_t a1 = mAES_s_box(a), b1 = mAES_s_box(b), c1 = mAES_s_box(c), d1 = mAES_s_box(d);
        const uint8_t a2 = f2(a1)       , b2 = f2(b1)       , c2 = f2(c1)       , d2 = f2(d1);

        dt[i+0] = a2     ^  b2^b1  ^  c1     ^  d1;
        dt[i+1] = a1     ^  b2     ^  c2^c1  ^  d1;
        dt[i+2] = a1     ^  b1     ^  c2     ^  d2^d1 ;
        dt[i+3] = a2^a1  ^  b1     ^  c1     ^  d2;
    }
}


/**
 *
 */
void mAES_inv_mix_sub_columns(uint8_t* dt, uint8_t* st)
{
    for (uint8_t i = 0 ; i < N_BLOCK ; i += N_COL)
    {
        const uint8_t a1 = st[i+0];
        const uint8_t b1 = st[i+1];
        const uint8_t c1 = st[i+2];
        const uint8_t d1 = st[i+3];

        const uint8_t a2 = f2(a1),  b2 = f2(b1),  c2 = f2(c1),  d2 = f2(d1);
        const uint8_t a4 = f2(a2),  b4 = f2(b2),  c4 = f2(c2),  d4 = f2(d2);
        const uint8_t a8 = f2(a4),  b8 = f2(b4),  c8 = f2(c4),  d8 = f2(d4);

        const uint8_t a9 = a8 ^ a1, b9 = b8 ^ b1, c9 = c8 ^ c1, d9 = d8 ^ d1;
        const uint8_t ac = a8 ^ a4, bc = b8 ^ b4, cc = c8 ^ c4, dc = d8 ^ d4;

        dt[ i             ] = mAES_is_box(ac^a2  ^  b9^b2  ^  cc^c1  ^  d9   );
        dt[(i +  5) & 0x0F] = mAES_is_box(a9     ^  bc^b2  ^  c9^c2  ^  dc^d1);
        dt[(i + 10) & 0x0F] = mAES_is_box(ac^a1  ^  b9     ^  cc^c2  ^  d9^d2);
        dt[(i + 15) & 0x0F] = mAES_is_box(a9^a2  ^  bc^b1  ^  c9     ^  dc^d2);
    }
}


/**
 *
 */
uint8_t  mAES_EncryptBlock(uint8_t* block)
{
    if (mAes.Round == 0) return ERROR;

    uint8_t           s1[N_BLOCK];
    mAES_copy_and_key(s1, block, mAes.Key);

    uint8_t r;
    for (   r = 1 ; r < mAes.Round ; ++r)
    {
        uint8_t              s2[N_BLOCK];
        mAES_mix_sub_columns(s2, s1);
        mAES_copy_and_key(   s1, s2, mAes.Key + (r * N_BLOCK));
    }

    mAES_shift_sub_rows(s1);
    mAES_copy_and_key(block, s1, mAes.Key + (r * N_BLOCK));

    return SUCCESS;
}


/**
 *
 */
uint8_t  mAES_EncryptCBC(uint8_t* data, uint8_t* cipher, const uint8_t blocks)
{
    uint8_t aux[N_BLOCK];

    // Start with the initialization vector
    memcpy(aux, mAes.Iv.Data, N_BLOCK);

    for (uint8_t index = 0; index < blocks; ++index)
    {
        mAES_xor_block(aux, data);

        if (mAES_EncryptBlock(aux) != SUCCESS) return ERROR;

        memcpy(cipher, aux, N_BLOCK);

        data   += N_BLOCK;
        cipher += N_BLOCK;
    }

    return SUCCESS ;
}


/**
 *
 */
uint8_t  mAES_DecryptBlock(uint8_t* cipher, uint8_t* data)
{
    if (mAes.Round == 0) return ERROR;

    uint8_t                 s1[N_BLOCK];
    mAES_copy_and_key(      s1, cipher, mAes.Key + (mAes.Round * N_BLOCK)) ;
    mAES_inv_shift_sub_rows(s1);

    for (uint8_t r = mAes.Round; --r;)
    {
        uint8_t                  s2[N_BLOCK];
        mAES_copy_and_key(       s2, s1, mAes.Key + (r * N_BLOCK));
        mAES_inv_mix_sub_columns(s1, s2) ;
    }

    mAES_copy_and_key(data, s1, mAes.Key);

    return SUCCESS;
}


/**
 *
 */
uint8_t  mAES_DecryptCBC(uint8_t* cipher, uint8_t* data, const uint8_t blocks)
{
    uint8_t aux[N_BLOCK];

    // Start with the initialization vector
    memcpy(aux, mAes.Iv.Data, N_BLOCK);

    for (uint8_t index = 0; index < blocks; ++index)
    {
        uint8_t tmp[N_BLOCK] ;
        memcpy( tmp, cipher, N_BLOCK);

        if (mAES_DecryptBlock(cipher, data) != SUCCESS) return ERROR;

        mAES_xor_block(data, aux);

        memcpy(aux, tmp, N_BLOCK) ;

        data   += N_BLOCK;
        cipher += N_BLOCK;
    }

    return SUCCESS;
}
