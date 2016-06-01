// Copyright (c) 2016 Matt Corallo
// Unlike the rest of Bitcoin Core, this file is
// distributed under the Affero General Public License (AGPL v3)

#include "bench.h"

#include "blockencodings.h"
#include "consensus/merkle.h"
#include "fec.h"
#include "random.h"
#include "txmempool.h"
#include "utiltime.h"

#include "version.h"
#include "streams.h"

#include "bench/data/block413567.hex.h"

#include <random>

#define DIV_CEIL(a, b) (((a) + (b) - 1) / (b))

class Receiver {
private:
    std::vector<unsigned char> data;
    std::unique_ptr<FECDecoder> decoder;
    PartiallyDownloadedChunkBlock partialBlock;
    bool header_done = false, block_done = false;
    size_t header_chunk_count, block_size;

    size_t *total_chunks_consumed, *total_chunks_in_mempool, *non_fec_chunks;

public:
    Receiver(CTxMemPool& poolIn, size_t *total_chunks_consumed_in, size_t *total_chunks_in_mempool_in, size_t *non_fec_chunks_in)
        : partialBlock(&poolIn), total_chunks_consumed(total_chunks_consumed_in),
        total_chunks_in_mempool(total_chunks_in_mempool_in), non_fec_chunks(non_fec_chunks_in) {}

    ~Receiver() { assert(header_done && block_done); }

    void InitHeader(size_t header_size, size_t total_chunks, int32_t prng_seed) {
        header_chunk_count = DIV_CEIL(header_size, FEC_CHUNK_SIZE);
        decoder.reset(new FECDecoder(header_size, total_chunks, prng_seed));
        data.resize(total_chunks * FEC_CHUNK_SIZE);
        (*non_fec_chunks) += header_chunk_count;
    }

    void RecvHeaderChunk(const unsigned char* chunk, size_t idx) {
        if (header_done)
            return;

        memcpy(&data[idx * FEC_CHUNK_SIZE], chunk, FEC_CHUNK_SIZE);
        assert(decoder->ProvideChunk(&data[idx * FEC_CHUNK_SIZE], idx));
        if (decoder->DecodeReady()) {
            std::vector<unsigned char> header_data(header_chunk_count * FEC_CHUNK_SIZE);
            for (size_t i = 0; i < header_chunk_count; i++)
                memcpy(&header_data[i * FEC_CHUNK_SIZE], decoder->GetDataPtr(i), FEC_CHUNK_SIZE);


            CBlockHeaderAndLengthShortTxIDs shortIDs;
            VectorInputStream stream(&header_data, SER_NETWORK, PROTOCOL_VERSION);
            stream >> shortIDs;

            assert(partialBlock.InitData(shortIDs) == READ_STATUS_OK);

            header_done = true;
        }
        (*total_chunks_consumed)++;
    }

    void InitBlock(size_t block_size_in, size_t total_chunks, int32_t prng_seed) {
        assert(header_done);

        block_size = block_size_in;
        decoder.reset(new FECDecoder(block_size, total_chunks, prng_seed));
        data.resize((total_chunks - DIV_CEIL(block_size, FEC_CHUNK_SIZE)) * FEC_CHUNK_SIZE);
        (*non_fec_chunks) += DIV_CEIL(block_size, FEC_CHUNK_SIZE);

        for (size_t i = 0; i < DIV_CEIL(block_size, FEC_CHUNK_SIZE); i++) {
            if (partialBlock.IsChunkAvailable(i)) {
                assert(decoder->ProvideChunk(partialBlock.GetChunk(i), i));
                (*total_chunks_in_mempool)++;
            }
        }
    }

    bool RecvBlockChunk(const unsigned char* chunk, size_t idx) {
        if (block_done)
            return true;

        unsigned char *dest = NULL;
        if (idx >= DIV_CEIL(block_size, FEC_CHUNK_SIZE))
            dest = &data[(idx - DIV_CEIL(block_size, FEC_CHUNK_SIZE)) * FEC_CHUNK_SIZE];
        else if (!partialBlock.IsChunkAvailable(idx)) {
            dest = partialBlock.GetChunk(idx);
            partialBlock.MarkChunkAvailable(idx);
        }
        if (dest == NULL)
            return false;

        memcpy(dest, chunk, FEC_CHUNK_SIZE);
        assert(decoder->ProvideChunk(dest, idx));

        if (decoder->DecodeReady()) {
            for (size_t i = 0; i < DIV_CEIL(block_size, FEC_CHUNK_SIZE); i++) {
                if (!partialBlock.IsChunkAvailable(i)) {
                    memcpy(partialBlock.GetChunk(i), decoder->GetDataPtr(i), FEC_CHUNK_SIZE);
                    partialBlock.MarkChunkAvailable(i);
                }
            }

            assert(partialBlock.FinalizeBlock() == READ_STATUS_OK);
            assert(partialBlock.GetBlock().GetHash() == uint256S("0000000000000000025aff8be8a55df8f89c77296db6198f272d6577325d4069"));
            bool mutated;
            assert(partialBlock.GetBlock().hashMerkleRoot == BlockMerkleRoot(partialBlock.GetBlock(), &mutated));
            assert(!mutated);

            block_done = true;
            return true;
        }

        (*total_chunks_consumed)++;
        return false;
    }
};

void Send(CBlock& block, int32_t prng_seed, Receiver& recv) {
    CBlockHeaderAndLengthShortTxIDs headerAndIDs(block);
    ChunkCodedBlock fecBlock(block, headerAndIDs);

    std::vector<unsigned char> header_data;
    VectorOutputStream stream(&header_data, SER_NETWORK, PROTOCOL_VERSION);
    stream << headerAndIDs;

    size_t header_size = header_data.size();
    std::vector<unsigned char> header_fec_chunks(2*(DIV_CEIL(header_size, FEC_CHUNK_SIZE) + 10) * FEC_CHUNK_SIZE);
    FECEncoder header_encoder(&header_data, prng_seed, &header_fec_chunks);

    recv.InitHeader(header_size, DIV_CEIL(header_size, FEC_CHUNK_SIZE) + header_fec_chunks.size() / FEC_CHUNK_SIZE, prng_seed);

    std::mt19937 g(0xdeadbeef);

    for (size_t i = 0; i < DIV_CEIL(header_size, FEC_CHUNK_SIZE); i++) {
        std::vector<unsigned char>::iterator endit = header_data.begin() + std::min(header_size, (i+1) * FEC_CHUNK_SIZE);
        std::vector<unsigned char> chunk(header_data.begin() + i * FEC_CHUNK_SIZE, endit);
        chunk.resize(FEC_CHUNK_SIZE);
        if (g() & 3)
            recv.RecvHeaderChunk(&chunk[0], i);
    }

    for (size_t i = 0; i < 2 * DIV_CEIL(header_size, FEC_CHUNK_SIZE) + 10; i++) {
        assert(header_encoder.BuildChunk(i));
        if (g() & 3)
            recv.RecvHeaderChunk(&header_fec_chunks[i * FEC_CHUNK_SIZE], i + DIV_CEIL(header_size, FEC_CHUNK_SIZE));
    }

    size_t block_size = fecBlock.GetCodedBlock().size();
    std::vector<unsigned char> block_fec_chunks(2 * (DIV_CEIL(block_size, FEC_CHUNK_SIZE) + 10) * FEC_CHUNK_SIZE);
    FECEncoder block_encoder(&fecBlock.GetCodedBlock(), prng_seed, &block_fec_chunks);

    std::vector<size_t> order(block_fec_chunks.size() / FEC_CHUNK_SIZE);
    for (size_t i = 0; i < block_fec_chunks.size() / FEC_CHUNK_SIZE; i++)
        order[i] = i;
    std::shuffle(order.begin(), order.end(), g);

    recv.InitBlock(block_size, DIV_CEIL(block_size, FEC_CHUNK_SIZE) + block_fec_chunks.size() / FEC_CHUNK_SIZE, prng_seed);

    for (size_t i = 0; i < block_fec_chunks.size() / FEC_CHUNK_SIZE; i++) {
        assert(block_encoder.BuildChunk(order[i]));
        if (g() & 3)
            recv.RecvBlockChunk(&block_fec_chunks[order[i] * FEC_CHUNK_SIZE], order[i] + DIV_CEIL(block_size, FEC_CHUNK_SIZE));
    }

    for (size_t i = 0; i < block_size / FEC_CHUNK_SIZE; i++) {
        if (g() & 3)
            if (recv.RecvBlockChunk(&fecBlock.GetCodedBlock()[i * FEC_CHUNK_SIZE], i))
                return;
    }
}

static void RealFECedBlockRoundTripTest(benchmark::State& state, int ntxn)
{
    CBlock block;

    CDataStream stream((const char*)blockencodings_tests::block413567,
            (const char*)&blockencodings_tests::block413567[sizeof(blockencodings_tests::block413567)],
            SER_NETWORK, PROTOCOL_VERSION);
    stream >> block;

    bool mutated;
    assert(block.hashMerkleRoot == BlockMerkleRoot(block, &mutated));
    assert(!mutated);
    assert(block.GetHash() == uint256S("0000000000000000025aff8be8a55df8f89c77296db6198f272d6577325d4069"));

    std::mt19937_64 g(0xdeadbeef);
    int32_t prng_seed = uint32_t(g()) & 0x7fffffff;

    std::vector<CTransaction> vtx2(block.vtx.begin() + 1, block.vtx.end());
    std::shuffle(vtx2.begin(), vtx2.end(), g);

    CMutableTransaction txtmp;
    txtmp.vin.resize(1);
    txtmp.vout.resize(1);
    txtmp.vout[0].nValue = 10;

    CTxMemPool pool(CFeeRate(0));
    for (int i = 0; i < ntxn; i++) {
        pool.addUnchecked(vtx2[i].GetHash(), CTxMemPoolEntry(vtx2[i], 0, 0, 0, 0, true, 0, false, 0, LockPoints()));
        for (int j = 0; j < 10; j++) {
            txtmp.vin[0].prevout.hash = GetRandHash();
            pool.addUnchecked(txtmp.GetHash(), CTxMemPoolEntry(txtmp, 0, 0, 0, 0, true, 0, false, 0, LockPoints()));
        }
    }

    size_t total_chunks_consumed, total_chunks_in_mempool, non_fec_chunks;
    while (state.KeepRunning()) {
        total_chunks_consumed = 0;
        total_chunks_in_mempool = 0;
        non_fec_chunks = 0;
        Receiver recv(pool, &total_chunks_consumed, &total_chunks_in_mempool, &non_fec_chunks);
        Send(block, prng_seed, recv);
    }

    fprintf(stderr, "Ate %lu/%lu chunks after getting %lu for free\n", total_chunks_consumed, non_fec_chunks, total_chunks_in_mempool);
}

static void FECBlockRTTest0(benchmark::State& state) { RealFECedBlockRoundTripTest(state, 0); }
static void FECBlockRTTest0500(benchmark::State& state) { RealFECedBlockRoundTripTest(state, 500); }
static void FECBlockRTTest1000(benchmark::State& state) { RealFECedBlockRoundTripTest(state, 1000); }
static void FECBlockRTTest1500(benchmark::State& state) { RealFECedBlockRoundTripTest(state, 1500); }
static void FECBlockRTTest1550(benchmark::State& state) { RealFECedBlockRoundTripTest(state, 1550); }

BENCHMARK(FECBlockRTTest0);
BENCHMARK(FECBlockRTTest0500);
BENCHMARK(FECBlockRTTest1000);
BENCHMARK(FECBlockRTTest1500);
BENCHMARK(FECBlockRTTest1550);
