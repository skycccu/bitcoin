// Copyright (c) 2012 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#include <math.h>
#include <stdlib.h>

#include "bloom.h"
#include "main.h"
#include "script.h"

#define LN2SQUARED 0.4804530139182014246671025263266649717305529515945455
#define LN2 0.6931471805599453094172321214581765680755001343602552

using namespace std;

static const unsigned char bit_mask[8] = {0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80};

CBloomFilter::CBloomFilter(unsigned int nElements, double nFPRate) :
vData(min((unsigned int)(-1  / LN2SQUARED * nElements * log(nFPRate)), MAX_BLOOM_FILTER_SIZE * 8) / 8),
nHashFuncs(min((unsigned int)(vData.size() * 8 / nElements * LN2), MAX_HASH_FUNCS))
{
}

inline uint32_t ROTL32 ( uint32_t x, int8_t r )
{
  return (x << r) | (x >> (32 - r));
}

unsigned int CBloomFilter::Hash(unsigned int nHashNum, const vector<unsigned char>& vDataToHash) const
{
    // The following is MurmurHash3 (x86_32), see http://code.google.com/p/smhasher/source/browse/trunk/MurmurHash3.cpp
    uint32_t h1 = nHashNum * (numeric_limits<uint32_t>::max() / (nHashFuncs-1));
    const uint32_t c1 = 0xcc9e2d51;
    const uint32_t c2 = 0x1b873593;

    const int nblocks = vDataToHash.size() / 4;

    //----------
    // body
    const uint32_t * blocks = (const uint32_t *)(&vDataToHash[0] + nblocks*4);

    for(int i = -nblocks; i; i++)
    {
        uint32_t k1 = blocks[i];

        k1 *= c1;
        k1 = ROTL32(k1,15);
        k1 *= c2;

        h1 ^= k1;
        h1 = ROTL32(h1,13); 
        h1 = h1*5+0xe6546b64;
    }

    //----------
    // tail
    const uint8_t * tail = (const uint8_t*)(&vDataToHash[0] + nblocks*4);

    uint32_t k1 = 0;

    switch(vDataToHash.size() & 3)
    {
    case 3: k1 ^= tail[2] << 16;
    case 2: k1 ^= tail[1] << 8;
    case 1: k1 ^= tail[0];
            k1 *= c1; k1 = ROTL32(k1,15); k1 *= c2; h1 ^= k1;
    };

    //----------
    // finalization
    h1 ^= vDataToHash.size();
    h1 ^= h1 >> 16;
    h1 *= 0x85ebca6b;
    h1 ^= h1 >> 13;
    h1 *= 0xc2b2ae35;
    h1 ^= h1 >> 16;

    return h1 % (vData.size() * 8);
}

void CBloomFilter::insert(const vector<unsigned char>& vKey)
{
    for (unsigned int i = 0; i < nHashFuncs; i++)
    {
        unsigned int nIndex = Hash(i, vKey);
        vData[nIndex >> 3] |= bit_mask[7 & nIndex];
    }
}

void CBloomFilter::insert(const COutPoint& outpoint)
{
    CDataStream stream(SER_NETWORK, PROTOCOL_VERSION);
    stream << outpoint;
    vector<unsigned char> data(stream.begin(), stream.end());
    insert(data);
}

void CBloomFilter::insert(const uint256& hash)
{
    vector<unsigned char> data(hash.begin(), hash.end());
    insert(data);
}

bool CBloomFilter::contains(const vector<unsigned char>& vKey) const
{
    for (unsigned int i = 0; i < nHashFuncs; i++)
    {
        unsigned int nIndex = Hash(i, vKey);
        if (!(vData[nIndex >> 3] & bit_mask[7 & nIndex]))
            return false;
    }
    return true;
}

bool CBloomFilter::contains(const COutPoint& outpoint) const
{
    CDataStream stream(SER_NETWORK, PROTOCOL_VERSION);
    stream << outpoint;
    vector<unsigned char> data(stream.begin(), stream.end());
    return contains(data);
}

bool CBloomFilter::contains(const uint256& hash) const
{
    vector<unsigned char> data(hash.begin(), hash.end());
    return contains(data);
}

bool CBloomFilter::IsWithinSizeConstraints() const
{
    return vData.size() <= MAX_BLOOM_FILTER_SIZE && nHashFuncs <= MAX_HASH_FUNCS;
}

bool CBloomFilter::IsTransactionRelevantToFilter(const CTransaction& tx) const
{
    // Match if the filter contains the hash of tx
    //  for finding tx when they appear in a block
    if (contains(tx.GetHash()))
        return true;

    BOOST_FOREACH(const CTxOut& txout, tx.vout)
    {
        // Match if the filter contains any arbitrary script data element in any scriptPubKey in tx
        CScript::const_iterator pc = txout.scriptPubKey.begin();
        vector<unsigned char> data;
        while (pc < txout.scriptPubKey.end())
        {
            opcodetype opcode;
            if (!txout.scriptPubKey.GetOp(pc, opcode, data))
                break;
            if (data.size() != 0 && contains(data))
                return true;
        }
    }

    BOOST_FOREACH(const CTxIn& txin, tx.vin)
    {
        // Match if the filter contains an outpoint tx spends
        if (contains(txin.prevout))
            return true;

        // Match if the filter contains any arbitrary script data element in any scriptSig in tx
        CScript::const_iterator pc = txin.scriptSig.begin();
        vector<unsigned char> data;
        while (pc < txin.scriptSig.end())
        {
            opcodetype opcode;
            if (!txin.scriptSig.GetOp(pc, opcode, data))
                break;
            if (data.size() != 0 && contains(data))
                return true;
        }
    }

    return false;
}
