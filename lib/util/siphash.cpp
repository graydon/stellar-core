#include "siphash.h"
#include <string.h>

#define U8TO64_LE(p) \
    (((uint64_t)((p)[0])) | ((uint64_t)((p)[1]) << 8) | \
     ((uint64_t)((p)[2]) << 16) | ((uint64_t)((p)[3]) << 24) | \
     ((uint64_t)((p)[4]) << 32) | ((uint64_t)((p)[5]) << 40) | \
     ((uint64_t)((p)[6]) << 48) | ((uint64_t)((p)[7]) << 56))

SipHash::SipHash(const unsigned char key[16], int c, int d)
{
    this->c = c;
    this->d = d;

    uint64_t k0 = U8TO64_LE(key);
    uint64_t k1 = U8TO64_LE(key + 8);

    this->v0 = (0x736f6d6570736575 ^ k0);
    this->v1 = (0x646f72616e646f6d ^ k1);
    this->v2 = (0x6c7967656e657261 ^ k0);
    this->v3 = (0x7465646279746573 ^ k1);

    this->m_idx = 0;
    this->input_len = 0;
    this->m = 0;
}

SipHash::~SipHash()
{
}

uint64_t
SipHash::digest()
{
    while (m_idx < 7)
    {
        m |= 0 << (m_idx++ * 8);
    }

    m |= ((uint64_t)input_len) << (m_idx * 8);

    digest_block();

    v2 ^= 0xff;

    for (int i = 0; i < d; i++)
    {
        compress();
    }

    return ((uint64_t)v0 ^ v1 ^ v2 ^ v3);
}
