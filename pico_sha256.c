/**
 * Copyright (c) 2021 CarlosFTM
 *
 * Calculates SHA256 Hast of a text message
 */

#include <stdio.h>
#include "pico/stdlib.h"
#include "hardware/gpio.h"

/* Text message */
uint8_t *message = "CarlosFTM 2021";  // SHA256: 7da203af51afa41a3636d1bf926c0a72a49e1e7440563eb53cf59cd8019b144d

uint32_t h[8] =
    {
        0x6a09e667,
        0xbb67ae85,
        0x3c6ef372,
        0xa54ff53a,
        0x510e527f,
        0x9b05688c,
        0x1f83d9ab,
        0x5be0cd19};

uint32_t hash[8] = {0};

const uint32_t k[64] =
    {
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

uint32_t data[64] = {0};            // Buffer used to calculate the Hash
uint8_t *pData = (uint8_t *)data;   // Byte Pointer to data[]

void conv_word_to_bigendian(uint32_t *Buffer, uint32_t numOfWords)
{
    for (uint32_t j = 0; j < numOfWords; j++)
    {
        uint32_t tmp1 = ((Buffer[j] << 24) | ((Buffer[j] << 8) & 0x00FF0000) | ((Buffer[j] >> 8) & 0x0000ff00) | (Buffer[j] >> 24));
        Buffer[j] = tmp1;
    }
    return;
}

bool data_init(uint8_t *inputData, uint8_t *output)
{
    // Copy Text to Data Buffer
    uint8_t msgSize = 0;
    uint8_t cnt = 0;

    for (uint32_t j = 0; j < 64; j++)
    {
        output[j] = 0;
    }

    //Get the size of the text message
    while (inputData[msgSize] != '\0')
    {
        msgSize++;
    }

    msgSize = msgSize; // NULL char not counted

    for (uint32_t cnt = 0; cnt < (msgSize); cnt++)
    {
        output[cnt] = inputData[cnt];
    }

    // Append a b10000000 to indicate end of the text
    output[msgSize] = 0x80;

    //to little endian
    uint32_t msgWordSize = msgSize / 4;
    if (msgSize % 4)
    {
        msgWordSize++;
    }

    conv_word_to_bigendian((uint32_t *)output, msgWordSize);

    // Append on the last 64-bits the lenght on bits of the message
    output[63] = 8 * msgSize;

    conv_word_to_bigendian((uint32_t *)&output[60], 1); // point to byte 0 of the DWORD

    return true;
}

uint32_t left_rotate(uint32_t data, uint32_t numBits)
{
    uint32_t x1 = (data << numBits);
    uint32_t x2 = (data >> (32 - numBits));
    uint32_t x3 = x1 | x2;
    return x3;
}

int right_rotate(uint32_t data, uint32_t numBits)
{
    uint32_t x1 = (data >> numBits);
    uint32_t x2 = (data << (32 - numBits));
    uint32_t x3 = x1 | x2;
    return x3;
}

void chunk_loop(uint32_t *dataChunk)
{
    uint32_t s0;
    uint32_t s1;
    uint32_t tmp0;
    uint32_t tmp1;
    uint32_t tmp2;

    for (uint32_t cnt = 16; cnt < 64; cnt++)
    {
        tmp0 = right_rotate(dataChunk[cnt - 15], 7);
        tmp1 = right_rotate(dataChunk[cnt - 15], 18);
        tmp2 = (dataChunk[cnt - 15] >> 3);
        s0 = (tmp0 ^ tmp1 ^ tmp2);
        s1 = (right_rotate(dataChunk[cnt - 2], 17) ^ right_rotate(dataChunk[cnt - 2], 19) ^ dataChunk[cnt - 2] >> 10);
        dataChunk[cnt] = dataChunk[cnt - 16] + s0 + dataChunk[cnt - 7] + s1;
    }
}

bool compression_loop(uint32_t *dataCompress)
{
    volatile uint32_t va = h[0];
    volatile uint32_t vb = h[1];
    volatile uint32_t vc = h[2];
    volatile uint32_t vd = h[3];
    volatile uint32_t ve = h[4];
    volatile uint32_t vf = h[5];
    volatile uint32_t vg = h[6];
    volatile uint32_t vh = h[7];

    for (uint32_t cnt = 0; cnt < 64; cnt++)
    {
        uint32_t s1 = right_rotate(ve, 6) ^ right_rotate(ve, 11) ^ right_rotate(ve, 25);
        uint32_t ch = (ve & vf) ^ ((~ve) & vg);
        uint32_t temp1 = vh + s1 + ch + k[cnt] + data[cnt];

        uint32_t s0 = right_rotate(va, 2) ^ right_rotate(va, 13) ^ right_rotate(va, 22);
        uint32_t maj = (va & vb) ^ (va & vc) ^ (vb & vc);
        uint32_t temp2 = s0 + maj;
        vh = vg;
        vg = vf;
        vf = ve;
        ve = vd + temp1;
        vd = vc;
        vc = vb;
        vb = va;
        va = temp1 + temp2;
    }

    hash[0] = h[0] + va;
    hash[1] = h[1] + vb;
    hash[2] = h[2] + vc;
    hash[3] = h[3] + vd;
    hash[4] = h[4] + ve;
    hash[5] = h[5] + vf;
    hash[6] = h[6] + vg;
    hash[7] = h[7] + vh;

    return true;
}


int main()
{
    stdio_init_all();
    const uint LED_PIN = 25;
    gpio_init(LED_PIN);
    gpio_set_dir(LED_PIN, GPIO_OUT);

    while (true)
    {
        do
        {
            data_init(message, pData);
            chunk_loop(data);
            compression_loop(data);
            uint32_t *p_msg = (uint32_t *)&message[0];
        } while ((hash[0] & 0xFFF00000) != 0x00000000);

        for (uint32_t j = 0; j < 8; j++)
        {
            printf("%08x", hash[j]);
        }
        printf(" - [%d] \n", data[0]);
        gpio_put(LED_PIN, 1);
        sleep_ms(100);
        gpio_put(LED_PIN, 0);
        sleep_ms(200);
    }
    return 0;
}
