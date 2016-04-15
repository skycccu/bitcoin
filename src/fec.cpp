// Copyright (c) 2016 Matt Corallo
// Unlike the rest of Bitcoin Core, this file is
// distributed under the Affero General Public License (AGPL v3)

#include "fec.h"
#include "util.h"

#include <stdio.h>
#include <string.h>

#define DIV_CEIL(a, b) (((a) + (b) - 1) / (b))

FECDecoder::FECDecoder(size_t data_size, size_t chunks_provided, int32_t prng_seed) :
        chunk_count(DIV_CEIL(data_size, FEC_CHUNK_SIZE)), chunks_recvd(0),
        chunks_sent(chunks_provided), decodeComplete(false),
        chunk_recvd_flags(chunks_sent), chunk_recvd_set(chunks_sent + 1) {
    session.reset(new LDPCFecSession());
    assert(session->InitSession(chunk_count, chunks_sent - chunk_count, FEC_CHUNK_SIZE, FLAG_DECODER, prng_seed, TypeSTAIRS) == LDPC_OK);
}

bool FECDecoder::ProvideChunk(unsigned char* chunk, size_t chunk_id) {
    assert(chunk_id < chunks_sent);

    if (decodeComplete)
        return true;

    if (chunk_recvd_flags[chunk_id])
        return true;

    if (session->DecodingStepWithSymbol((void**)&chunk_recvd_set[0], chunk, chunk_id) == LDPC_OK) {
        chunk_recvd_flags[chunk_id] = true;
        chunks_recvd++;
        return true;
    }
    return false;
}

bool FECDecoder::HasChunk(size_t chunk_id) {
    assert(chunk_id < chunks_sent);

    return decodeComplete || chunk_recvd_flags[chunk_id];
}

bool FECDecoder::DecodeReady() const {
    if (chunks_recvd < chunk_count) {
        if (chunks_recvd % 15 == 0)
            LogPrint("fec", "FEC: Got %lu of %lu minimum chunks\n", chunks_recvd, chunk_count);
        return false;
    }
    if (decodeComplete)
        return true;

    if (const_cast<LDPCFecSession&>(*session).IsDecodingComplete((void**)&chunk_recvd_set[0])) {
        decodeComplete = true;
        LogPrintf("FEC: Decoding complete\n");
        return true;
    }

    if ((chunks_recvd - chunk_count) % 10 == 9)
        LogPrint("fec", "FEC: Decoding failed with %lu/%lu\n", chunks_recvd, chunk_count);

    return false;
}

const void* FECDecoder::GetDataPtr(size_t chunk_id) const {
    assert(DecodeReady());
    assert(chunk_id < chunk_count);
    return chunk_recvd_set[chunk_id];
}


FECEncoder::FECEncoder(const std::vector<unsigned char>* dataIn, const int32_t prng_seed, std::vector<unsigned char>* fec_chunksIn)
        : data(dataIn), fec_chunks(fec_chunksIn) {
    assert(fec_chunks->size() % FEC_CHUNK_SIZE == 0);
    assert(!fec_chunks->empty());
    assert(!data->empty());

    const size_t data_chunk_count = DIV_CEIL(data->size(), FEC_CHUNK_SIZE);
    const size_t fec_chunk_count = fec_chunks->size() / FEC_CHUNK_SIZE;

    session.reset(new LDPCFecSession());
    assert(session->InitSession(data_chunk_count, fec_chunk_count, FEC_CHUNK_SIZE, FLAG_CODER, prng_seed, TypeSTAIRS) == LDPC_OK);

    chunk_ptrs.resize(data_chunk_count + fec_chunk_count);
    for (uint32_t i = 0; i < data_chunk_count - 1; i++)
        chunk_ptrs[i] = const_cast<void*> ((void*)(&(*data)[i * FEC_CHUNK_SIZE]));

    if (data->size() % FEC_CHUNK_SIZE == 0) {
        chunk_ptrs[data_chunk_count - 1] = const_cast<void*> ((void*)(&(*data)[(data_chunk_count - 1) * FEC_CHUNK_SIZE]));
    } else {
        memcpy(last_chunk, &(*data)[(data_chunk_count - 1) * FEC_CHUNK_SIZE], data->size() % FEC_CHUNK_SIZE);
        memset(last_chunk + (data->size() % FEC_CHUNK_SIZE), 0, FEC_CHUNK_SIZE - (data->size() % FEC_CHUNK_SIZE));
        chunk_ptrs[data_chunk_count - 1] = last_chunk;
    }
}

bool FECEncoder::BuildChunk(size_t fec_chunk_id) {
    assert(fec_chunk_id < fec_chunks->size() / FEC_CHUNK_SIZE);
    size_t final_chunk_id, chunk_id;
    final_chunk_id = chunk_id = fec_chunk_id + DIV_CEIL(data->size(), FEC_CHUNK_SIZE);
    assert(chunk_id < chunk_ptrs.size());

    if (chunk_ptrs[chunk_id])
        return true;

    while (chunk_ptrs[chunk_id - 1] == NULL)
        chunk_id--;

    for (; chunk_id <= final_chunk_id; chunk_id++) {
        fec_chunk_id = chunk_id - DIV_CEIL(data->size(), FEC_CHUNK_SIZE);
        chunk_ptrs[chunk_id] = &(*fec_chunks)[fec_chunk_id * FEC_CHUNK_SIZE];
        if (session->BuildParitySymbol(&chunk_ptrs[0], fec_chunk_id, chunk_ptrs[chunk_id]) != LDPC_OK)
            return false;
    }
    return true;
}

bool FECEncoder::PrefillChunks() {
    return BuildChunk((fec_chunks->size() / FEC_CHUNK_SIZE) - 1);
}

bool BuildFECChunks(const std::vector<unsigned char>& data, const int32_t prng_seed, std::vector<unsigned char>& fec_chunks) {
    FECEncoder enc(&data, prng_seed, &fec_chunks);
    for (size_t i = 0; i < fec_chunks.size() / FEC_CHUNK_SIZE; i++)
        if (!enc.BuildChunk(i))
            return false;
    return true;
}
