#pragma once


/******************************************************************************
 * Defines                                                                    *
 ******************************************************************************/

#define N_ROW                  4
#define N_COL                  4
#define N_BLOCK                (N_ROW * N_COL)
#define N_MAX_ROUNDS           14
#define KEY_SCHEDULE_BYTES     ((N_MAX_ROUNDS + 1) * N_BLOCK)

typedef struct
{
    struct
    {
        uint8_t Data[AES_BUFFER_SIZE];
        uint8_t Index;
    }
    Buffer;

    struct
    {
        uint8_t Data[N_BLOCK];
        uint8_t Length;
    }
    Iv;

    uint8_t Round;
    uint8_t Key[KEY_SCHEDULE_BYTES];
}
AES_t;


/******************************************************************************
 * Functions                                                                  *
 ******************************************************************************/
void     AES_Init(            void);
uint8_t  AES_IvSize(          void);
void     AES_IvGet(           uint8_t*      iv);
uint8_t  AES_IvSet(           uint8_t*      iv, const uint8_t size);
uint8_t  AES_IvRandomize(     const uint8_t size);
uint8_t  AES_KeySet(          uint8_t*      key   ,
                              uint16_t      keylen);

uint8_t  AES_SizeAfterPadding(const uint8_t size);

uint8_t  AES_Padding(         uint8_t*      data      , const uint8_t size, uint8_t* padded);
uint8_t  AES_Encrypt(         uint8_t*      text      , const uint8_t size, uint8_t* ciphertext);
uint8_t  AES_Decrypt(         uint8_t*      ciphertext, const uint8_t size, uint8_t* text);
