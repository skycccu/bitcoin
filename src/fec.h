// Copyright (c) 2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_FEC_H
#define BITCOIN_FEC_H

#include <assert.h>
#include <memory>
#include <stdint.h>
#include <vector>

#include "fec/ldpc_fec.h"

class FECDecoder {
private:
    size_t chunk_count, chunks_recvd, chunks_sent, first_missing_chunk;
    mutable bool decodeComplete;
    std::vector<bool> chunk_recvd_flags;
    std::vector<unsigned char*> chunk_recvd_set;

    std::unique_ptr<LDPCFecSession> session;
public:
    FECDecoder(size_t data_size, size_t chunks_provided, int32_t prng_seed);
    FECDecoder() {}

    bool ProvideChunk(unsigned char* chunk, size_t chunk_id);
    bool HasChunk(size_t chunk_id);
    bool DecodeReady() const;
    const void* GetDataPtr(size_t chunk_id) const;
};

class FECEncoder {
private:
    const std::vector<unsigned char>* data;
    std::vector<unsigned char>* fec_chunks;
    std::vector<void*> chunk_ptrs;
    std::unique_ptr<LDPCFecSession> session;

    unsigned char last_chunk[FEC_CHUNK_SIZE];
public:
    // dataIn/fec_chunksIn must not change during lifetime of this object
    FECEncoder(const std::vector<unsigned char>* dataIn, const int32_t prng_seed, std::vector<unsigned char>* fec_chunksIn);
    bool BuildChunk(size_t fec_chunk_id);
    bool PrefillChunks();
};

bool BuildFECChunks(const std::vector<unsigned char>& data, const int32_t prng_seed, std::vector<unsigned char>& fec_chunks);

#endif
