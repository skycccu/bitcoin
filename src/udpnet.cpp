// Copyright (c) 2016 Matt Corallo
// Unlike the rest of Bitcoin Core, this file is
// distributed under the Affero General Public License (AGPL v3)

#if defined(HAVE_CONFIG_H)
#include "config/bitcoin-config.h"
#endif

#include "udpnet.h"

#include "blockencodings.h"
#include "chainparams.h"
#include "consensus/validation.h"
#include "compat/endian.h"
#include "fec.h"
#include "hash.h"
#include "main.h"
#include "net.h"
#include "primitives/block.h"
#include "timedata.h"
#include "util.h"
#include "utiltime.h"

#include <sys/socket.h>

#include <event2/event.h>

#include <boost/thread.hpp>
#include <boost/static_assert.hpp>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <mutex>
#include <thread>
#include <random>

// 1 Gbps - DO NOT CHANGE, this determines encoding, see do_send_messages to actually change upload speed
#define NETWORK_TARGET_BYTES_PER_SECOND (1024 * 1024 * 1024 / 8)

static int udp_sock; // The socket we use to send/recv (bound to *:GetUDPInboundPort)

static const uint32_t UDP_PROTOCOL_VERSION = (1 << 16) | 1; // Min version 1, current version 1

enum UDPMessageType {
    MSG_TYPE_SYN = 0,
    MSG_TYPE_KEEPALIVE = 1, // aka SYN_ACK
    MSG_TYPE_DISCONNECT = 2,
    MSG_TYPE_BLOCK_HEADER = 3,
    MSG_TYPE_BLOCK_CONTENTS = 4,
    MSG_TYPE_PING = 5,
    MSG_TYPE_PONG = 6,
};

struct __attribute__((packed)) UDPMessageHeader {
    uint64_t chk1;
    uint64_t chk2;
    uint8_t msg_type; // A UDPMessageType
};
BOOST_STATIC_ASSERT_MSG(sizeof(UDPMessageHeader) == 17, "__attribute__((packed)) must work");

// Message body cannot exceed 1045 bytes (1063 bytes in total UDP message contents, with a padding byte in message)
#define MAX_UDP_MESSAGE_LENGTH 1045

enum UDPBlockMessageFlags {
    HAVE_BLOCK = 1,
};

struct __attribute__((packed)) UDPBlockMessage {
    uint64_t hash_prefix; // First 8 bytes of blockhash, interpreted in LE (note that this will not include 0s, those are at the end)
    int32_t  prng_seed;
    uint32_t obj_length; // Size of full FEC-coded data
    uint16_t chunks_sent; // Total chunks including source and repair chunks
    uint16_t chunk_id;
    uint8_t block_flags; // Flags as defined by UDPBlockMessageFlags
    unsigned char data[FEC_CHUNK_SIZE];
};
#define UDP_BLOCK_METADATA_LENGTH (sizeof(UDPBlockMessage) - sizeof(UDPBlockMessage::data))
BOOST_STATIC_ASSERT_MSG(sizeof(UDPBlockMessage) <= MAX_UDP_MESSAGE_LENGTH, "Messages must be <= MAX_UDP_MESSAGE_LENGTH");

struct __attribute__((packed)) UDPMessage {
    UDPMessageHeader header;
    union __attribute__((packed)) {
        unsigned char message[MAX_UDP_MESSAGE_LENGTH + 1];
        uint64_t longint;
        struct UDPBlockMessage block;
    } msg;
};
BOOST_STATIC_ASSERT_MSG(sizeof(UDPMessage) == 1063, "__attribute__((packed)) must work");
#define PACKET_SIZE (sizeof(UDPMessage) + 40 + 8)
BOOST_STATIC_ASSERT_MSG(PACKET_SIZE <= 1280, "All packets must fit in min-MTU for IPv6");
BOOST_STATIC_ASSERT_MSG(sizeof(UDPMessage) == sizeof(UDPMessageHeader) + MAX_UDP_MESSAGE_LENGTH + 1, "UDPMessage should have 1 padding byte");

enum UDPState {
    STATE_INIT = 0, // Indicating the node was just added
    STATE_GOT_SYN = 1, // We received their SYN
    STATE_GOT_SYN_ACK = 1 << 1, // We've received a KEEPALIVE (which they only send after receiving our SYN)
    STATE_INIT_COMPLETE = STATE_GOT_SYN | STATE_GOT_SYN_ACK, // We can now send data to this peer
};

struct PartialBlockData {
    const int64_t timeHeaderRecvd;
    const CService nodeHeaderRecvd;

    std::atomic_bool in_header; // Indicates we are currently downloading header (or block txn)
    std::atomic_bool initialized; // Indicates Init has been called in current in_header state

    std::mutex state_mutex;
    // Background thread is preparing to, and is submitting to core
    // This is set with state_mutex held, and afterwards block_data and
    // nodesWithChunksAvailableSet should be treated read-only.
    std::atomic_bool currentlyProcessing;

    uint32_t obj_length; // FEC-coded length of currently-being-download object
    uint32_t chunks_sent;
    std::vector<unsigned char> data_recvd;
    FECDecoder decoder;
    PartiallyDownloadedChunkBlock block_data;

    // nodes with chunks_avail set -> packets that were useful, packets provided
    std::map<CService, std::pair<uint32_t, uint32_t> > nodesWithChunksAvailableSet;

    bool Init(const UDPMessage& msg);
    ReadStatus ProvideHeaderData(const CBlockHeaderAndLengthShortTxIDs& header);
    PartialBlockData(const CService& node, const UDPMessage& header_msg); // Must be a MSG_TYPE_BLOCK_HEADER
};

class ChunksAvailableSet {
private:
    int32_t header_chunk_count;
    bool allSent;
    uint8_t bitset[496]; // We can only track a total of ~4MB of header+block data+fec chunks...should be plenty
public:
    ChunksAvailableSet(bool hasAllChunks) : header_chunk_count(-1), allSent(hasAllChunks) { if (!allSent) memset(bitset, 0, sizeof(bitset)); }
    bool IsHeaderChunkAvailable(uint16_t chunk_id) const {
        if (allSent) return true;
        if (chunk_id / 8 > sizeof(bitset)) return false;
        return ((bitset[chunk_id / 8] >> (chunk_id & 7)) & 1);
    }
    void SetHeaderChunkAvailable(uint16_t chunk_id) {
        if (allSent) return;
        if (chunk_id / 8 > sizeof(bitset)) return;
        bitset[chunk_id / 8]  |= 1 << (chunk_id & 7);
    }
    void SetHeaderDataAndFECChunkCount(uint16_t chunks_sent) { header_chunk_count = chunks_sent; }
    bool IsBlockChunkAvailable(uint16_t chunk_id) const {
        if (allSent) return true;
        if (header_chunk_count == -1) return false;
        uint32_t bitset_id = header_chunk_count + chunk_id;
        if (bitset_id / 8 > sizeof(bitset)) return false;
        return ((bitset[bitset_id / 8] >> (bitset_id & 7)) & 1);
    }
    void SetBlockChunkAvailable(uint16_t chunk_id) {
        if (allSent) return;
        if (header_chunk_count == -1) return;
        uint32_t bitset_id = header_chunk_count + chunk_id;
        if (bitset_id / 8 > sizeof(bitset)) return;
        bitset[bitset_id / 8]  |= 1 << (bitset_id & 7);
    }

    void SetAllAvailable() { allSent = true; }
    bool AreAllAvailable() const { return allSent; }
};

struct UDPConnectionInfo {
    uint64_t local_magic;  // Already LE
    uint64_t remote_magic; // Already LE
    bool fTrusted;
};

struct UDPConnectionState {
    UDPConnectionInfo connection;
    int state; // Flags from UDPState
    uint32_t protocolVersion;
    int64_t lastSendTime;
    int64_t lastRecvTime;
    int64_t lastPingTime;
    std::map<uint64_t, int64_t> ping_times;
    std::map<uint64_t, ChunksAvailableSet> chunks_avail;
};
#define PROTOCOL_VERSION_MIN(ver) (((ver) >> 16) & 0xffff)
#define PROTOCOL_VERSION_CUR(ver) (((ver) >>  0) & 0xffff)
#define PROTOCOL_VERSION_FLAGS(ver) (((ver) >> 32) & 0xffffffff)

static std::recursive_mutex cs_mapUDPNodes;
static std::map<CService, UDPConnectionState> mapUDPNodes;
static std::map<int64_t, std::pair<CService, uint64_t> > nodesToRepeatDisconnect;
static std::map<CService, UDPConnectionInfo> mapPersistentNodes;

static CService TRUSTED_PEER_DUMMY;
static std::map<std::pair<uint64_t, CService>, std::shared_ptr<PartialBlockData> > mapPartialBlocks;
static std::set<uint64_t> setBlocksRelayed;

static std::map<std::pair<uint64_t, CService>, std::shared_ptr<PartialBlockData> >::iterator RemovePartialBlock(std::map<std::pair<uint64_t, CService>, std::shared_ptr<PartialBlockData> >::iterator it) {
    // TODO: If its from a trusted peer, maybe add to setBlocksRelayed so we dont try it again?
    uint64_t hash_prefix = it->first.first;
    std::lock_guard<std::mutex> lock(it->second->state_mutex);
    // Note that we do not modify nodesWithChunksAvailableSet, as it might be "read-only" due to currentlyProcessing
    for (const std::pair<CService, std::pair<uint32_t, uint32_t> >& node : it->second->nodesWithChunksAvailableSet) {
        std::map<CService, UDPConnectionState>::iterator nodeIt = mapUDPNodes.find(node.first);
        if (nodeIt == mapUDPNodes.end())
            continue;
        std::map<uint64_t, ChunksAvailableSet>::iterator chunks_avail_it = nodeIt->second.chunks_avail.find(hash_prefix);
        if (chunks_avail_it == nodeIt->second.chunks_avail.end())
            continue; // Peer reconnected at some point
        nodeIt->second.chunks_avail.erase(chunks_avail_it);
    }
    return mapPartialBlocks.erase(it);
}

static void RemovePartialBlock(const std::pair<uint64_t, CService>& key) {
    auto it = mapPartialBlocks.find(key);
    if (it != mapPartialBlocks.end())
        RemovePartialBlock(it);
}

static void RemovePartialBlocks(uint64_t hash_prefix) {
    std::map<std::pair<uint64_t, CService>, std::shared_ptr<PartialBlockData> >::iterator it = mapPartialBlocks.lower_bound(std::make_pair(hash_prefix, TRUSTED_PEER_DUMMY));
    while (it != mapPartialBlocks.end() && it->first.first == hash_prefix)
        it = RemovePartialBlock(it);
}

//TODO: Switch to something faster than SHA256 for checksums
static void FillChecksum(uint64_t magic, UDPMessage& msg, const unsigned int length) {
    assert(length <= sizeof(UDPMessage));
    CSHA256 hasher;
    uint256 h;
    hasher.Write((unsigned char*)&magic, sizeof(magic)).Write((unsigned char*)&msg.header.msg_type, length - 16).Finalize(h.begin());
    msg.header.chk1 = htole64(h.GetUint64(0));
    msg.header.chk2 = htole64(h.GetUint64(1));
}
static bool CheckChecksum(uint64_t magic, const UDPMessage& msg, const unsigned int length) {
    assert(length <= sizeof(UDPMessage));
    CSHA256 hasher;
    uint256 h;
    hasher.Write((unsigned char*)&magic, sizeof(magic)).Write((unsigned char*)&msg.header.msg_type, length - 16).Finalize(h.begin());
    return msg.header.chk1 == htole64(h.GetUint64(0)) && msg.header.chk2 == htole64(h.GetUint64(1));
}
static void SendMessage(const UDPMessage& msg, const unsigned int length, const CService& service, const uint64_t magic);
static void SendMessage(const UDPMessage& msg, const unsigned int length, const std::map<CService, UDPConnectionState>::const_iterator& node);
static void DisconnectNode(const std::map<CService, UDPConnectionState>::iterator& it);



/**
 * Block compression/decompression follows
 */

static void SendMessageToNode(const UDPMessage& msg, unsigned int length, uint64_t hash_prefix, std::map<CService, UDPConnectionState>::iterator it) {
    if ((it->second.state & STATE_INIT_COMPLETE) != STATE_INIT_COMPLETE)
        return;
    const auto chunks_avail_it = it->second.chunks_avail.find(hash_prefix);

    bool use_chunks_avail = chunks_avail_it != it->second.chunks_avail.end();
    if (use_chunks_avail) {
        if (chunks_avail_it->second.AreAllAvailable())
            return;

        if (msg.header.msg_type == MSG_TYPE_BLOCK_HEADER) {
            chunks_avail_it->second.SetHeaderDataAndFECChunkCount(le32toh(msg.msg.block.chunks_sent));
            if (chunks_avail_it->second.IsHeaderChunkAvailable(le32toh(msg.msg.block.chunk_id)))
                return;
        } else if (chunks_avail_it->second.IsBlockChunkAvailable(le32toh(msg.msg.block.chunk_id)))
            return;
    }

    SendMessage(msg, length, it);

    if (use_chunks_avail) {
        if (msg.header.msg_type == MSG_TYPE_BLOCK_HEADER)
            chunks_avail_it->second.SetHeaderChunkAvailable(le32toh(msg.msg.block.chunk_id));
        else if (msg.header.msg_type == MSG_TYPE_BLOCK_CONTENTS)
            chunks_avail_it->second.SetBlockChunkAvailable(le32toh(msg.msg.block.chunk_id));
    }
}

static void SendMessageToAllNodes(const UDPMessage& msg, unsigned int length, uint64_t hash_prefix) {
    for (std::map<CService, UDPConnectionState>::iterator it = mapUDPNodes.begin(); it != mapUDPNodes.end(); it++)
        SendMessageToNode(msg, length, hash_prefix, it);
}

#define DIV_CEIL(a, b) (((a) + (b) - 1) / (b))
static void SendMessageData(UDPMessage& msg, const std::vector<unsigned char>& data, uint64_t hash_prefix) {
    const size_t msg_chunks = DIV_CEIL(data.size(), FEC_CHUNK_SIZE);

    for (auto it = mapUDPNodes.begin(); it != mapUDPNodes.end(); it++) {
        auto send_it = it;
        for (uint16_t i = 0; i < msg_chunks; i++) {
            msg.msg.block.chunk_id = htole16(i);

            size_t msg_size = i == msg_chunks - 1 ? (data.size() % FEC_CHUNK_SIZE) : sizeof(msg.msg.block.data);
            if (msg_size == 0)
                msg_size = FEC_CHUNK_SIZE;
            memcpy(msg.msg.block.data, &data[i * FEC_CHUNK_SIZE], msg_size);
            if (msg_size != sizeof(msg.msg.block.data))
                memset(&msg.msg.block.data[msg_size], 0, sizeof(msg.msg.block.data) - msg_size);

            SendMessageToNode(msg, sizeof(UDPMessageHeader) + sizeof(UDPBlockMessage), hash_prefix, send_it);
            send_it++;
            if (send_it == mapUDPNodes.end())
                send_it = mapUDPNodes.begin();
        }
    }
}

struct DataFECer {
    size_t fec_chunks;
    std::vector<unsigned char> fec_data;
    FECEncoder enc;
    DataFECer(const std::vector<unsigned char>& data, int32_t of_prng_seed, size_t fec_chunks_in) :
        fec_chunks(fec_chunks_in),
        fec_data(fec_chunks * FEC_CHUNK_SIZE),
        enc(&data, of_prng_seed, &fec_data) {}
};

static void SendFECData(UDPMessage& msg, DataFECer& fec, size_t msg_chunks, uint64_t hash_prefix) {
    assert(fec.fec_chunks > 9);

    std::vector<size_t> order(fec.fec_chunks);
    std::mt19937 g(GetTimeMicros());
    for (size_t i = 0; i < fec.fec_chunks; i++)
        order[i] = i;
    // Because the mempool-block-fill isnt started until the first non-header
    // packet, we want to get one non-header packet out to each node quick
    std::shuffle(order.begin() + std::min(mapUDPNodes.size() * 2, (size_t)5), order.end(), g);

    for (auto it = mapUDPNodes.begin(); it != mapUDPNodes.end(); it++) {
        auto send_it = it;
        for (uint16_t i = 0; i < fec.fec_chunks; i++) {
            assert(fec.enc.BuildChunk(order[i])); // TODO: Handle errors?

            msg.msg.block.chunk_id = htole16(order[i] + msg_chunks);
            memcpy(msg.msg.block.data, &fec.fec_data[order[i] * FEC_CHUNK_SIZE], FEC_CHUNK_SIZE);

            SendMessageToNode(msg, sizeof(UDPMessageHeader) + sizeof(UDPBlockMessage), hash_prefix, send_it);
            send_it++;
            if (send_it == mapUDPNodes.end())
                send_it = mapUDPNodes.begin();
        }
    }
}

static void SendFECedData(const uint256& blockhash, UDPMessageType type, const std::vector<unsigned char>& data, DataFECer& fec, int32_t of_prng_seed) {
    const size_t msg_chunks = DIV_CEIL(data.size(), FEC_CHUNK_SIZE);
    assert(msg_chunks + fec.fec_chunks < std::numeric_limits<uint16_t>::max());

    uint64_t hash_prefix = blockhash.GetUint64(0);

    // First fill in common message elements
    UDPMessage msg;
    msg.header.msg_type        = type;
    msg.msg.block.hash_prefix  = htole64(hash_prefix);
    msg.msg.block.prng_seed    = htole32(of_prng_seed);
    msg.msg.block.obj_length   = htole32(data.size());
    msg.msg.block.chunks_sent  = htole16(msg_chunks + fec.fec_chunks);
    msg.msg.block.block_flags  = HAVE_BLOCK;

    // For header messages, the actual data is more useful.
    // For block contents, the probably generated most chunks from the header + mempool.
    // We send in usefulness-first order
    if (type == MSG_TYPE_BLOCK_HEADER) {
        SendMessageData(msg, data, hash_prefix);
        SendFECData(msg, fec, msg_chunks, hash_prefix);
    } else {
        SendFECData(msg, fec, msg_chunks, hash_prefix);
        SendMessageData(msg, data, hash_prefix);
    }
}

#define to_millis_double(t) (std::chrono::duration_cast<std::chrono::duration<double, std::chrono::milliseconds::period> >(t).count())

static boost::thread *process_block_thread = NULL;
void UDPRelayBlock(const CBlock& block) {
    std::chrono::steady_clock::time_point start;
    const bool fBench = LogAcceptCategory("bench");
    if (fBench)
        start = std::chrono::steady_clock::now();

    uint256 hashBlock = block.GetHash();
    uint64_t hash_prefix = hashBlock.GetUint64(0);
    std::unique_lock<std::recursive_mutex> lock(cs_mapUDPNodes, std::defer_lock);

    {
        int32_t of_prng_seed = (int32_t)(hashBlock.GetUint64(1) & 0x7fffffff);

        const std::vector<unsigned char> *block_chunks = NULL;
        bool skipEncode = false;
        std::unique_lock<std::mutex> partial_block_lock;
        bool inUDPProcess = process_block_thread && boost::this_thread::get_id() == process_block_thread->get_id();
        if (inUDPProcess) {
            lock.lock();

            auto it = mapPartialBlocks.find(std::make_pair(hash_prefix, TRUSTED_PEER_DUMMY));
            if (it != mapPartialBlocks.end() && it->second->currentlyProcessing) {
                partial_block_lock = std::unique_lock<std::mutex>(it->second->state_mutex); // Locked after cs_mapUDPNodes
                if (it->second->block_data.AreChunksAvailable()) {
                    if (fBench)
                        LogPrintf("UDP: Building FEC chunks from decoded block\n");
                    skipEncode = true;
                    block_chunks = &it->second->block_data.GetCodedBlock();
                } else {
                    partial_block_lock.unlock();
                    lock.unlock();
                }
            }
        }

        ChunkCodedBlock *codedBlock = (ChunkCodedBlock*) alloca(sizeof(ChunkCodedBlock));
        std::vector<unsigned char> data;
        VectorOutputStream stream(&data, SER_NETWORK, PROTOCOL_VERSION);
        CBlockHeaderAndLengthShortTxIDs headerAndIDs(block, true);
        stream << headerAndIDs;

        std::chrono::steady_clock::time_point coded;
        if (fBench)
            coded = std::chrono::steady_clock::now();

        DataFECer header_fecer(data, of_prng_seed,
                (NETWORK_TARGET_BYTES_PER_SECOND / 1000 / PACKET_SIZE / 4) + 10); // 1ms/4 nodes + 10 chunks of header FEC

        DataFECer *block_fecer = (DataFECer*) alloca(sizeof(DataFECer));
        if (inUDPProcess) {
            // If we're actively receiving UDP packets, go ahead and spend the time to precalculate FEC now,
            // otherwise we want to start getting the header/first block chunks out ASAP
            header_fecer.enc.PrefillChunks();

            if (!skipEncode) {
                new (codedBlock) ChunkCodedBlock(block, headerAndIDs);
                block_chunks = &codedBlock->GetCodedBlock();
            }
            if (!block_chunks->empty()) {
                new (block_fecer) DataFECer(*block_chunks, of_prng_seed,
                        DIV_CEIL(block_chunks->size(), FEC_CHUNK_SIZE) + 10); //TODO: Pick something different?
                block_fecer->enc.PrefillChunks();
            }
        }

        std::chrono::steady_clock::time_point feced;
        if (fBench)
            feced = std::chrono::steady_clock::now();

        // We do all the expensive calculations before locking cs_mapUDPNodes
        // so that the forward-packets-without-block logic in HandleBlockMessage
        // continues without interruption as long as possible
        if (!lock)
            lock.lock();

        if (mapUDPNodes.empty())
            return;

        if (setBlocksRelayed.count(hash_prefix))
            return;

        SendFECedData(hashBlock, MSG_TYPE_BLOCK_HEADER, data, header_fecer, of_prng_seed);

        std::chrono::steady_clock::time_point header_sent;
        if (fBench)
            header_sent = std::chrono::steady_clock::now();

        if (!inUDPProcess) { // We sent header before calculating any block stuff
            if (!skipEncode) {
                new (codedBlock) ChunkCodedBlock(block, headerAndIDs);
                block_chunks = &codedBlock->GetCodedBlock();
            }
            if (!block_chunks->empty()) {
                new (block_fecer) DataFECer(*block_chunks, of_prng_seed,
                        DIV_CEIL(block_chunks->size(), FEC_CHUNK_SIZE) + 10); //TODO: Pick something different?
            }
        }

        std::chrono::steady_clock::time_point block_coded;
        if (fBench)
            block_coded = std::chrono::steady_clock::now();

        // Now (maybe) send the transaction chunks
        if (!block_chunks->empty())
            SendFECedData(hashBlock, MSG_TYPE_BLOCK_CONTENTS, *block_chunks, *block_fecer, of_prng_seed);

        if (fBench) {
            std::chrono::steady_clock::time_point all_sent(std::chrono::steady_clock::now());
            LogPrintf("UDP: Built all FEC chunks for block %s in %lf %lf %lf %lf %lf ms\n", hashBlock.ToString(), to_millis_double(coded - start), to_millis_double(feced - coded), to_millis_double(header_sent - feced), to_millis_double(block_coded - header_sent), to_millis_double(all_sent - block_coded));
            if (!inUDPProcess)
                LogPrintf("UDP: Block %s had serialized size %lu\n", hashBlock.ToString(), block.GetSerializeSize(SER_NETWORK, PROTOCOL_VERSION));
        } else
            LogPrintf("UDP: Built all FEC chunks for block %s\n", hashBlock.ToString());

        if (!skipEncode)
            codedBlock->~ChunkCodedBlock();

        if (!block_chunks->empty())
            block_fecer->~DataFECer();

        // Destroy partial_block_lock before we RemovePartialBlocks()
    }

    setBlocksRelayed.insert(hash_prefix);
    RemovePartialBlocks(hash_prefix);
}

static std::mutex block_process_mutex;
static std::condition_variable block_process_cv;
static std::atomic_bool block_process_shutdown(false);
static std::vector<std::pair<std::pair<uint64_t, CService>, std::shared_ptr<PartialBlockData> > > block_process_queue;

static void DoBackgroundBlockProcessing(const std::pair<std::pair<uint64_t, CService>, std::shared_ptr<PartialBlockData> >& block_data) {
    // If we just blindly call ProcessNewBlock here, we have a cs_main/cs_mapUDPNodes inversion
    // (actually because fucking P2P code calls everything with cs_main already locked).
    // Instead we pass the processing back to ProcessNewBlockThread without cs_mapUDPNodes
    std::unique_lock<std::mutex> lock(block_process_mutex);
    block_process_queue.emplace_back(block_data);
    lock.unlock();
    block_process_cv.notify_all();
}

static void ProcessBlockThread() {
    while (true) {
        std::unique_lock<std::mutex> process_lock(block_process_mutex);
        while (block_process_queue.empty() && !block_process_shutdown)
            block_process_cv.wait(process_lock);
        if (block_process_shutdown)
            return;
        // To avoid vector re-allocation we pop_back, so its secretly a stack, shhhhh, dont tell anyone
        std::pair<std::pair<uint64_t, CService>, std::shared_ptr<PartialBlockData> > process_block = block_process_queue.back();
        block_process_queue.pop_back();
        process_lock.unlock();

        std::unique_lock<std::mutex> lock(process_block.second->state_mutex);
        if (process_block.second->block_data.IsBlockAvailable()) {
            process_block.second->currentlyProcessing = true;

            ReadStatus status = process_block.second->block_data.FinalizeBlock();;
            if (status != READ_STATUS_OK) {
                lock.unlock();
                std::lock_guard<std::recursive_mutex> udpNodesLock(cs_mapUDPNodes);

                if (status == READ_STATUS_INVALID) {
                    if (process_block.first.second == TRUSTED_PEER_DUMMY)
                        LogPrintf("UDP: Unable to decode block from trusted peer(s), check your trusted peers are behaving well.\n");
                    else {
                        const auto it = mapUDPNodes.find(process_block.first.second);
                        if (it != mapUDPNodes.end())
                            DisconnectNode(it);
                    }
                }
                RemovePartialBlock(process_block.first);
                continue;
            } else {
                const CBlock& decoded_block = process_block.second->block_data.GetBlock();
                if (LogAcceptCategory("bench")) {
                    uint32_t total_chunks_recvd = 0, total_chunks_used = 0;
                    std::map<CService, std::pair<uint32_t, uint32_t> >& chunksProvidedByNode = process_block.second->nodesWithChunksAvailableSet;
                    for (const std::pair<CService, std::pair<uint32_t, uint32_t> >& provider : chunksProvidedByNode) {
                        total_chunks_recvd += provider.second.second;
                        total_chunks_used += provider.second.first;
                    }
                    LogPrintf("UDP: Block %s reconstructed from %s with %u chunks in %lf ms (%u recvd from %u peers)\n", decoded_block.GetHash().ToString(), process_block.second->nodeHeaderRecvd.ToString(), total_chunks_used, (GetTimeMicros() - process_block.second->timeHeaderRecvd) / 1000.0, total_chunks_recvd, chunksProvidedByNode.size());
                    for (const std::pair<CService, std::pair<uint32_t, uint32_t> >& provider : chunksProvidedByNode)
                        LogPrintf("UDP:    %u/%u used from %s\n", provider.second.first, provider.second.second, provider.first.ToString());
                }

                CValidationState validationstate;
                if (!CheckBlock(decoded_block, validationstate, Params().GetConsensus(), GetAdjustedTime())) {
                    LogPrintf("UDP: Failed to decode block %s (%s)\n", decoded_block.GetHash().ToString(), validationstate.GetRejectReason());
                    lock.unlock();
                    std::lock_guard<std::recursive_mutex> udpNodesLock(cs_mapUDPNodes);
                    RemovePartialBlock(process_block.first);
                    continue; // Probably a tx collision generating merkle-tree errors
                }

                lock.unlock();
                ProcessNewBlock(validationstate, Params(), NULL, &decoded_block, false, NULL);
                if (LogAcceptCategory("bench"))
                    LogPrintf("UDP: Block %s had serialized size %lu\n", decoded_block.GetHash().ToString(), decoded_block.GetSerializeSize(SER_NETWORK, PROTOCOL_VERSION));

                std::lock_guard<std::recursive_mutex> udpNodesLock(cs_mapUDPNodes);
                RemovePartialBlocks(process_block.first.first); // Ensure we remove even if we didnt UDPRelayBlock()
            }
        } else if (!process_block.second->in_header && process_block.second->initialized) {
            uint32_t mempool_provided_chunks = 0;
            uint32_t total_chunk_count = 0;
            uint256 blockHash;
            bool fDone = process_block.second->block_data.IsIterativeFillDone();
            while (!fDone) {
                size_t firstChunkProcessed;
                if (!lock)
                    lock.lock();
                if (!total_chunk_count) {
                    total_chunk_count = process_block.second->block_data.GetChunkCount();
                    blockHash = process_block.second->block_data.GetBlockHash();
                }
                ReadStatus res = process_block.second->block_data.DoIterativeFill(firstChunkProcessed);
                if (res != READ_STATUS_OK) {
                    lock.unlock();
                    std::lock_guard<std::recursive_mutex> udpNodesLock(cs_mapUDPNodes);
                    if (res == READ_STATUS_INVALID) {
                        if (process_block.first.second == TRUSTED_PEER_DUMMY)
                            LogPrintf("UDP: Unable to process mempool for block %s from trusted peer(s), check your trusted peers are behaving well.\n", blockHash.ToString());
                        else {
                            LogPrintf("UDP: Unable to process mempool for block %s from %s, disconnecting\n", blockHash.ToString(), process_block.first.second.ToString());
                            const auto it = mapUDPNodes.find(process_block.first.second);
                            if (it != mapUDPNodes.end())
                                DisconnectNode(it);
                        }
                    } else
                        LogPrintf("UDP: Unable to process mempool for block %s, dropping block\n", blockHash.ToString());
                    RemovePartialBlock(process_block.first);
                    break;
                } else {
                    while (firstChunkProcessed < total_chunk_count && process_block.second->block_data.IsChunkAvailable(firstChunkProcessed)) {
                        if (!process_block.second->decoder.HasChunk(firstChunkProcessed)) {
                            process_block.second->decoder.ProvideChunk(process_block.second->block_data.GetChunk(firstChunkProcessed), firstChunkProcessed);
                            mempool_provided_chunks++;
                        }
                        firstChunkProcessed++;
                    }

                    if (process_block.second->block_data.IsBlockAvailable()) {
                        DoBackgroundBlockProcessing(process_block);
                        break;
                    }
                }
                fDone = process_block.second->block_data.IsIterativeFillDone();
                if (fDone || mempool_provided_chunks % 50 == 49)
                    lock.unlock();
            }
            LogPrintf("UDP: Initialized block %s with %ld/%ld mempool-provided chunks (or more)\n", blockHash.ToString(), mempool_provided_chunks, total_chunk_count);
        }
    }
}

static void BlockRecvInit() {
    process_block_thread = new boost::thread(boost::bind(&TraceThread<void (*)()>, "udpprocess", &ProcessBlockThread));
}

static void BlockRecvShutdown() {
    if (process_block_thread) {
        block_process_shutdown = true;
        block_process_cv.notify_all();
        process_block_thread->join();
        delete process_block_thread;
        process_block_thread = NULL;
    }
}

ReadStatus PartialBlockData::ProvideHeaderData(const CBlockHeaderAndLengthShortTxIDs& header) {
    assert(in_header);
    in_header = false;
    initialized = false;
    return block_data.InitData(header);
}

bool PartialBlockData::Init(const UDPMessage& msg) {
    assert(msg.header.msg_type == MSG_TYPE_BLOCK_HEADER || msg.header.msg_type == MSG_TYPE_BLOCK_CONTENTS);
    obj_length  = msg.msg.block.obj_length;
    chunks_sent = msg.msg.block.chunks_sent;
    if (msg.header.msg_type == MSG_TYPE_BLOCK_HEADER)
        data_recvd.resize(chunks_sent * sizeof(UDPBlockMessage::data));
    else {
        if (DIV_CEIL(obj_length, FEC_CHUNK_SIZE) != block_data.GetChunkCount())
            return false;
        data_recvd.resize((chunks_sent - DIV_CEIL(obj_length, FEC_CHUNK_SIZE)) * sizeof(UDPBlockMessage::data));
    }
    decoder = FECDecoder(obj_length, chunks_sent, msg.msg.block.prng_seed);
    initialized = true;
    return true;
}

PartialBlockData::PartialBlockData(const CService& node, const UDPMessage& msg) :
        timeHeaderRecvd(GetTimeMicros()), nodeHeaderRecvd(node),
        in_header(true), initialized(false),
        currentlyProcessing(false), block_data(&mempool)
    { assert(Init(msg)); }

static bool HandleBlockMessage(UDPMessage& msg, size_t length, const CService& node, UDPConnectionState& state) {
    //TODO: There are way too many damn tree lookups here...either cut them down or increase parallelism

    assert(msg.header.msg_type == MSG_TYPE_BLOCK_HEADER || msg.header.msg_type == MSG_TYPE_BLOCK_CONTENTS);

    if (length != sizeof(UDPMessageHeader) + sizeof(UDPBlockMessage)) {
        LogPrintf("UDP: Got invalidly-sized block message from %s\n", node.ToString());
        return false;
    }

    msg.msg.block.hash_prefix = le64toh(msg.msg.block.hash_prefix);
    msg.msg.block.prng_seed   = le32toh(msg.msg.block.prng_seed);
    msg.msg.block.obj_length  = le32toh(msg.msg.block.obj_length);
    msg.msg.block.chunks_sent = le16toh(msg.msg.block.chunks_sent);
    msg.msg.block.chunk_id    = le16toh(msg.msg.block.chunk_id);

    const uint64_t hash_prefix = msg.msg.block.hash_prefix; // Need a reference in a few places, but its packed, so we can't have one directly

    if (msg.msg.block.obj_length > 2000000) {
        LogPrintf("UDP: Got massive obj_length of %u\n", msg.msg.block.obj_length);
        return false;
    }

    if (DIV_CEIL(msg.msg.block.obj_length, FEC_CHUNK_SIZE) > msg.msg.block.chunks_sent) {
        LogPrintf("UDP: Peer %s sent fewer chunks than object length\n", node.ToString());
        return false;
    }

    if (setBlocksRelayed.count(msg.msg.block.hash_prefix))
        return true;

    std::map<uint64_t, ChunksAvailableSet>::iterator chunks_avail_it = state.chunks_avail.find(msg.msg.block.hash_prefix);

    if (chunks_avail_it == state.chunks_avail.end()) {
        if (msg.header.msg_type == MSG_TYPE_BLOCK_HEADER) {
            if (state.chunks_avail.size() > 1 && !state.connection.fTrusted) {
                // Non-trusted nodes can only be forwarding up to 2 blocks at a time
                assert(state.chunks_avail.size() == 2);
                auto first_partial_block_it  = mapPartialBlocks.find(std::make_pair(state.chunks_avail. begin()->first, node));
                assert(first_partial_block_it != mapPartialBlocks.end());
                auto second_partial_block_it = mapPartialBlocks.find(std::make_pair(state.chunks_avail.rbegin()->first, node));
                assert(second_partial_block_it != mapPartialBlocks.end());
                if (first_partial_block_it->second->timeHeaderRecvd < second_partial_block_it->second->timeHeaderRecvd) {
                    state.chunks_avail.erase(first_partial_block_it->first.first);
                    mapPartialBlocks.erase(first_partial_block_it);
                } else {
                    state.chunks_avail.erase(second_partial_block_it->first.first);
                    mapPartialBlocks.erase(second_partial_block_it);
                }
            }
            // Once we add to chunks_avail, we MUST add to mapPartialBlocks->second->nodesWithChunksAvailableSet, or we will leak memory
            chunks_avail_it = state.chunks_avail.insert(std::make_pair(hash_prefix, ChunksAvailableSet(msg.msg.block.block_flags & HAVE_BLOCK))).first;
        } else // Probably stale (ie we just finished reconstructing
            return true;
    }

    if (msg.msg.block.block_flags & HAVE_BLOCK)
        chunks_avail_it->second.SetAllAvailable();
    else {
        // By calling Set*ChunkAvailable before SendMessageToNode's
        // SetHeaderDataAndFECChunkCount call, we will miss the first block packet we
        // receive and re-send that in UDPRelayBlock...this is OK because we'll save
        // more by doing this before the during-process relay below
        if (msg.header.msg_type == MSG_TYPE_BLOCK_HEADER)
            chunks_avail_it->second.SetHeaderChunkAvailable(msg.msg.block.chunk_id);
        else
            chunks_avail_it->second.SetBlockChunkAvailable(msg.msg.block.chunk_id);
    }


    std::map<std::pair<uint64_t, CService>, std::shared_ptr<PartialBlockData> >::iterator it = mapPartialBlocks.find(std::make_pair(hash_prefix, state.connection.fTrusted ? TRUSTED_PEER_DUMMY : node));
    if (it == mapPartialBlocks.end()) {
        if (msg.header.msg_type == MSG_TYPE_BLOCK_HEADER)
            it = mapPartialBlocks.insert(std::make_pair(std::make_pair(hash_prefix, state.connection.fTrusted ? TRUSTED_PEER_DUMMY : node), std::make_shared<PartialBlockData>(node, msg))).first;
        else // Probably stale (ie we just finished reconstructing)
            return true;
    }
    PartialBlockData& block = *it->second;

    std::unique_lock<std::mutex> block_lock(block.state_mutex, std::try_to_lock);

    if (state.connection.fTrusted && block.currentlyProcessing) {
        // It takes quite some time to decode the block and check its merkle tree
        // (10+ms) due to lots of SHA256 activity...
        // Thus, while the block is processing in ProcessNewBlockThread, we
        // continue forwarding chunks we received from trusted peers
        msg.msg.block.hash_prefix = htole32(msg.msg.block.hash_prefix);
        msg.msg.block.prng_seed   = htole32(msg.msg.block.prng_seed);
        msg.msg.block.obj_length  = htole32(msg.msg.block.obj_length);
        msg.msg.block.chunks_sent = htole16(msg.msg.block.chunks_sent);
        msg.msg.block.chunk_id    = htole16(msg.msg.block.chunk_id);
        msg.msg.block.block_flags = HAVE_BLOCK;
        SendMessageToAllNodes(msg, length, hash_prefix);
        return true;
    }

    if (!block_lock)
        block_lock.lock();

    // currentlyProcessing must come before any chunk-accessors in block.block_data
    // Additionally, IsBlockAvailable protects us from processing anything in the
    // time between when we submit the block and when the background thread picks it up.
    // Note that there is a crash there as well if we do not, for mempool-only blocks
    if (block.currentlyProcessing || (!block.in_header && block.block_data.IsBlockAvailable()))
        return true;

    std::map<CService, std::pair<uint32_t, uint32_t> >::iterator usefulChunksFromNodeIt =
            block.nodesWithChunksAvailableSet.insert(std::make_pair(node, std::make_pair(0, 0))).first;
    usefulChunksFromNodeIt->second.second++;

    if (msg.header.msg_type == MSG_TYPE_BLOCK_HEADER && !block.in_header)
        return true;
    if (msg.header.msg_type == MSG_TYPE_BLOCK_CONTENTS && block.in_header) {
        // Either we're getting packets out of order and wasting this packet,
        // or we didnt get enough header and will fail download anyway
        return true;
    }

    if (msg.header.msg_type == MSG_TYPE_BLOCK_CONTENTS && !block.initialized) {
        if (!block.Init(msg)) {
            LogPrintf("UDP: Got block contents that couldn't match header for block id %lu\n", msg.msg.block.hash_prefix);
            return true;
        }
        DoBackgroundBlockProcessing(*it); // Kick off mempool scan (waits on us to unlock block_lock)
    }

    if (msg.msg.block.obj_length  != block.obj_length ||
        msg.msg.block.chunks_sent != block.chunks_sent) {
        // Duplicate hash_prefix or bad trusted peer
        LogPrintf("UDP: Got wrong obj_length/chunsk_sent for block id %lu from peer %s! Check your trusted peers are behaving well\n", msg.msg.block.hash_prefix, node.ToString());
        return true;
    }

    if (msg.msg.block.chunk_id > block.chunks_sent) {
        LogPrintf("UDP: Got chunk out of range from %s\n", node.ToString());
        return false;
    }

    if (block.decoder.HasChunk(msg.msg.block.chunk_id))
        return true;

    unsigned char* dest = NULL;
    if (msg.header.msg_type == MSG_TYPE_BLOCK_HEADER)
        dest = &block.data_recvd[msg.msg.block.chunk_id * sizeof(UDPBlockMessage::data)];
    else {
        if (msg.msg.block.chunk_id < block.block_data.GetChunkCount()) {
            assert(!block.block_data.IsChunkAvailable(msg.msg.block.chunk_id)); // HasChunk should have returned false, then
            dest = block.block_data.GetChunk(msg.msg.block.chunk_id);
            block.block_data.MarkChunkAvailable(msg.msg.block.chunk_id);
        } else
            dest = &block.data_recvd[(msg.msg.block.chunk_id - block.block_data.GetChunkCount()) * sizeof(UDPBlockMessage::data)];
    }

    memcpy(dest, msg.msg.block.data, sizeof(UDPBlockMessage::data));
    if (!block.decoder.ProvideChunk(dest, msg.msg.block.chunk_id)) {
        // Not actually sure what can cause this, so we don't disconnect here
        LogPrintf("UDP: FEC chunk decode failed for chunk %d from block %lu from %s\n", msg.msg.block.chunk_id, msg.msg.block.hash_prefix, node.ToString());
        return true;
    }

    usefulChunksFromNodeIt->second.first++;

    if (state.connection.fTrusted) {
        msg.msg.block.hash_prefix = htole32(msg.msg.block.hash_prefix);
        msg.msg.block.prng_seed   = htole32(msg.msg.block.prng_seed);
        msg.msg.block.obj_length  = htole32(msg.msg.block.obj_length);
        msg.msg.block.chunks_sent = htole16(msg.msg.block.chunks_sent);
        msg.msg.block.chunk_id    = htole16(msg.msg.block.chunk_id);
        msg.msg.block.block_flags = 0;
        SendMessageToAllNodes(msg, length, hash_prefix);
    }

    if (block.decoder.DecodeReady()) {
        const bool fBench = LogAcceptCategory("bench");
        std::chrono::steady_clock::time_point decode_start;
        if (fBench)
            decode_start = std::chrono::steady_clock::now();

        for (uint32_t i = 0; i < DIV_CEIL(block.obj_length, sizeof(UDPBlockMessage::data)); i++) {
            const void* data_ptr = block.decoder.GetDataPtr(i);
            assert(data_ptr);

            unsigned char* dest = NULL;
            if (block.in_header) {
                dest = &block.data_recvd[i * sizeof(UDPBlockMessage::data)];
                if (dest == data_ptr)
                    continue;
            } else {
                if (!block.block_data.IsChunkAvailable(i)) {
                    dest = block.block_data.GetChunk(i);
                    block.block_data.MarkChunkAvailable(i);
                } else
                    continue;
            }

            if (block.in_header)
                assert(data_ptr < &block.data_recvd[0] || data_ptr > &block.data_recvd[block.obj_length]);
            else if (!block.in_header)
                assert(data_ptr != dest);
            memcpy(dest, data_ptr, sizeof(UDPBlockMessage::data));
        }
        std::chrono::steady_clock::time_point data_copied;
        if (fBench)
            data_copied = std::chrono::steady_clock::now();

        if (block.in_header) {
            CBlockHeaderAndLengthShortTxIDs header;
            try {
                CDataStream stream(block.data_recvd, SER_NETWORK, PROTOCOL_VERSION);
                stream >> header;
            } catch (std::ios_base::failure& e) {
                LogPrintf("UDP: Failed to decode received header and short txids from %s\n", node.ToString());
                return false;
            }
            std::chrono::steady_clock::time_point header_deserialized;
            if (fBench)
                header_deserialized = std::chrono::steady_clock::now();

            ReadStatus decode_status = block.ProvideHeaderData(header);
            if (decode_status == READ_STATUS_INVALID) {
                LogPrintf("UDP: Got invalid header and short txids from %s\n", node.ToString());
                return false;
            } else if (decode_status == READ_STATUS_FAILED) {
                LogPrintf("UDP: Failed to read header and short txids from %s\n", node.ToString());
                return true;
            }
            if (fBench) {
                std::chrono::steady_clock::time_point header_provided(std::chrono::steady_clock::now());
                LogPrintf("UDP: Got full header and shorttxids from %s in %lf %lf %lf ms\n", node.ToString(), to_millis_double(data_copied - decode_start), to_millis_double(header_deserialized - data_copied), to_millis_double(header_provided - header_deserialized));
            } else
                LogPrintf("UDP: Got full header and shorttxids from %s\n", node.ToString());
        } else
            assert(block.block_data.IsBlockAvailable());

        if (block.block_data.IsBlockAvailable()) {
            // We do not RemovePartialBlock as we want ChunkAvailableSets to be there when UDPRelayBlock gets called
            // from inside ProcessBlockThread, so after we notify the ProcessNewBlockThread we cannot access block.
            block_lock.unlock();
            DoBackgroundBlockProcessing(*it); // Decode block and call ProcessNewBlock
        }
    }

    return true;
}

static void ProcessDownloadTimerEvents() {
    std::unique_lock<std::recursive_mutex> lock(cs_mapUDPNodes);
    for (auto it = mapPartialBlocks.begin(); it != mapPartialBlocks.end();) {
        if (it->second->timeHeaderRecvd < GetTimeMicros() - 1000 * 1000 * 1000)
            it = RemovePartialBlock(it);
        else
            it++;
    }
    //TODO: Prune setBlocksRelayed to keep lookups fast?
}



/**
 * Init/shutdown logic follows
 */

static struct event_base* event_base_read = NULL;
static event *read_event, *timer_event;
static struct timeval timer_interval;

static void ThreadRunReadEventLoop() { event_base_dispatch(event_base_read); }
static void do_send_messages();
static void send_messages_flush_and_break();
static void ThreadRunWriteEventLoop() { do_send_messages(); }

static void read_socket_func(evutil_socket_t fd, short event, void* arg);
static void timer_func(evutil_socket_t fd, short event, void* arg);

static boost::thread *udp_write_thread = NULL, *udp_read_thread = NULL;

static void AddConnectionFromString(const std::string& node, bool fTrust) {
    size_t host_port_end = node.find(',');
    size_t local_pass_end = node.find(',', host_port_end + 1);
    size_t remote_pass_end = node.find(',', local_pass_end + 1);
    if (host_port_end == std::string::npos || local_pass_end == std::string::npos || remote_pass_end != std::string::npos) {
        LogPrintf("UDP: Failed to parse parameter to -add[trusted]udpnode: %s", node);
        return;
    }

    std::string host_port = node.substr(0, host_port_end);
    CService addr;
    if (!Lookup(host_port.c_str(), addr, -1, true) || !addr.IsValid()) {
        LogPrintf("UDP: Failed to lookup hostname for -add[trusted]udpnode: %s\n", host_port);
        return;
    }

    std::string local_pass = node.substr(host_port_end + 1, local_pass_end - host_port_end - 1);
    uint64_t local_magic = Hash(&local_pass[0], &local_pass[0] + local_pass.size()).GetUint64(0);
    std::string remote_pass = node.substr(local_pass_end + 1);
    uint64_t remote_magic = Hash(&remote_pass[0], &remote_pass[0] + local_pass.size()).GetUint64(0);

    OpenPersistentUDPConnectionTo(addr, local_magic, remote_magic, fTrust);
}

static void AddConfAddedConnections() {
    for (const std::string& node : mapMultiArgs["-addudpnode"])
        AddConnectionFromString(node, false);
    for (const std::string& node : mapMultiArgs["-addtrustedudpnode"])
        AddConnectionFromString(node, true);
}

bool InitializeUDPConnections() {
    assert(!udp_write_thread && !udp_read_thread);
    assert(GetUDPInboundPort());

    udp_sock = socket(AF_INET6, SOCK_DGRAM, 0);
    assert(udp_sock);

    int opt = 1;
    assert(setsockopt(udp_sock, SOL_SOCKET, SO_REUSEADDR, &opt,  sizeof(opt)) == 0);
    opt = 0;
    assert(setsockopt(udp_sock, IPPROTO_IPV6, IPV6_V6ONLY, &opt,  sizeof(opt)) == 0);
    fcntl(udp_sock, F_SETFL, fcntl(udp_sock, F_GETFL) | O_NONBLOCK);

    struct sockaddr_in6 wildcard;
    memset(&wildcard, 0, sizeof(wildcard));
    wildcard.sin6_family = AF_INET6;
    memcpy(&wildcard.sin6_addr, &in6addr_any, sizeof(in6addr_any));
    wildcard.sin6_port = htons(GetUDPInboundPort());

    if (bind(udp_sock, (sockaddr*) &wildcard, sizeof(wildcard))) {
        close(udp_sock);
        return false;
    }

    event_base_read = event_base_new();
    if (!event_base_read) {
        close(udp_sock);
        return false;
    }

    read_event = event_new(event_base_read, udp_sock, EV_READ | EV_PERSIST, read_socket_func, NULL);
    if (!read_event) {
        event_base_free(event_base_read);
        close(udp_sock);
        return false;
    }

    event_add(read_event, NULL);
    timer_event = event_new(event_base_read, -1, EV_PERSIST, timer_func, NULL);
    if (!timer_event) {
        event_free(read_event);
        event_base_free(event_base_read);
        close(udp_sock);
        return false;
    }
    timer_interval.tv_sec = 0;
    timer_interval.tv_usec = 500*1000;
    evtimer_add(timer_event, &timer_interval);

    udp_read_thread = new boost::thread(boost::bind(&TraceThread<void (*)()>, "udpread", &ThreadRunReadEventLoop));
    udp_write_thread = new boost::thread(boost::bind(&TraceThread<void (*)()>, "udpwrite", &ThreadRunWriteEventLoop));

    AddConfAddedConnections();

    BlockRecvInit();

    return true;
}

void StopUDPConnections() {
    if (!udp_write_thread && !udp_read_thread)
        return;
    assert(udp_write_thread && udp_read_thread);

    BlockRecvShutdown();

    event_base_loopbreak(event_base_read);
    udp_read_thread->join();
    delete udp_read_thread;

    std::unique_lock<std::recursive_mutex> lock(cs_mapUDPNodes);
    UDPMessage msg;
    msg.header.msg_type = MSG_TYPE_DISCONNECT;
    for (std::map<CService, UDPConnectionState>::iterator it = mapUDPNodes.begin(); it != mapUDPNodes.end(); it++)
        SendMessage(msg, sizeof(UDPMessageHeader), it);
    mapUDPNodes.clear();

    send_messages_flush_and_break();

    udp_write_thread->join();
    delete udp_write_thread;

    event_free(read_event);
    event_free(timer_event);
    event_base_free(event_base_read);

    close(udp_sock);
}



/**
 * Network handling follows
 */

static std::map<CService, UDPConnectionState>::iterator silent_disconnect(const std::map<CService, UDPConnectionState>::iterator& it) {
    return mapUDPNodes.erase(it);
}

static std::map<CService, UDPConnectionState>::iterator send_and_disconnect(const std::map<CService, UDPConnectionState>::iterator& it) {
    UDPMessage msg;
    msg.header.msg_type = MSG_TYPE_DISCONNECT;
    SendMessage(msg, sizeof(UDPMessageHeader), it);

    int64_t now = GetTimeMillis();
    while (!nodesToRepeatDisconnect.insert(std::make_pair(now + 1000, std::make_pair(it->first, it->second.connection.remote_magic))).second)
        now++;
    assert(nodesToRepeatDisconnect.insert(std::make_pair(now + 10000, std::make_pair(it->first, it->second.connection.remote_magic))).second);

    return silent_disconnect(it);
}

static void DisconnectNode(const std::map<CService, UDPConnectionState>::iterator& it) {
    send_and_disconnect(it);
}

static void read_socket_func(evutil_socket_t fd, short event, void* arg) {
    const bool fBench = LogAcceptCategory("bench");
    std::chrono::steady_clock::time_point start;
    if (fBench)
        start = std::chrono::steady_clock::now();

    UDPMessage msg;
    struct sockaddr_in6 remoteaddr;
    socklen_t remoteaddrlen = sizeof(remoteaddr);

    ssize_t res = recvfrom(udp_sock, &msg, sizeof(msg), MSG_DONTWAIT, (sockaddr*)&remoteaddr, &remoteaddrlen);
    assert(res >= 0);
    assert(remoteaddrlen == sizeof(remoteaddr));

    if (size_t(res) < sizeof(UDPMessageHeader) || size_t(res) == sizeof(UDPMessage))
        return;

    std::unique_lock<std::recursive_mutex> lock(cs_mapUDPNodes);
    std::map<CService, UDPConnectionState>::iterator it = mapUDPNodes.find(remoteaddr);
    if (it == mapUDPNodes.end())
        return;
    if (!CheckChecksum(it->second.connection.local_magic, msg, res))
        return;

    UDPConnectionState& state = it->second;

    state.lastRecvTime = GetTimeMillis();
    if (msg.header.msg_type == MSG_TYPE_SYN) {
        if (res != sizeof(UDPMessageHeader) + 8) {
            LogPrintf("UDP: Got invalidly-sized SYN message from %s\n", it->first.ToString());
            send_and_disconnect(it);
            return;
        }

        state.protocolVersion = le64toh(msg.msg.longint);
        if (PROTOCOL_VERSION_MIN(state.protocolVersion) > 1) {
            LogPrintf("UDP: Got min protocol version we didnt understand (%u:%u) from %s\n", PROTOCOL_VERSION_MIN(state.protocolVersion), PROTOCOL_VERSION_CUR(state.protocolVersion), it->first.ToString());
            send_and_disconnect(it);
            return;
        }

        if (!(state.state & STATE_GOT_SYN))
            state.state |= STATE_GOT_SYN;
    } else if (msg.header.msg_type == MSG_TYPE_KEEPALIVE) {
        if (res != sizeof(UDPMessageHeader)) {
            LogPrintf("UDP: Got invalidly-sized KEEPALIVE message from %s\n", it->first.ToString());
            send_and_disconnect(it);
            return;
        }
        if ((state.state & STATE_INIT_COMPLETE) != STATE_INIT_COMPLETE)
            LogPrint("udpnet", "UDP: Successfully connected to %s!\n", it->first.ToString());

        // If we get a SYNACK without a SYN, that probably means we were restarted, but the other side wasn't
        // ...this means the other side thinks we're fully connected, so just switch to that mode
        state.state |= STATE_GOT_SYN_ACK | STATE_GOT_SYN;
    } else if (msg.header.msg_type == MSG_TYPE_DISCONNECT) {
        LogPrintf("UDP: Got disconnect message from %s\n", it->first.ToString());
        silent_disconnect(it);
        return;
    }

    if (!(state.state & STATE_INIT_COMPLETE))
        return;

    if (msg.header.msg_type == MSG_TYPE_BLOCK_HEADER || msg.header.msg_type == MSG_TYPE_BLOCK_CONTENTS) {
        if (!HandleBlockMessage(msg, res, it->first, it->second)) {
            send_and_disconnect(it);
            return;
        }
    } else if (msg.header.msg_type == MSG_TYPE_PING) {
        if (res != sizeof(UDPMessageHeader) + 8) {
            LogPrintf("UDP: Got invalidly-sized PING message from %s\n", it->first.ToString());
            send_and_disconnect(it);
            return;
        }

        msg.header.msg_type = MSG_TYPE_PONG;
        SendMessage(msg, sizeof(UDPMessageHeader) + 8, it);
    } else if (msg.header.msg_type == MSG_TYPE_PONG) {
        if (res != sizeof(UDPMessageHeader) + 8) {
            LogPrintf("UDP: Got invalidly-sized PONG message from %s\n", it->first.ToString());
            send_and_disconnect(it);
            return;
        }

        uint64_t nonce = le64toh(msg.msg.longint);
        std::map<uint64_t, int64_t>::iterator nonceit = state.ping_times.find(nonce);
        if (nonceit == state.ping_times.end()) // Possibly duplicated packet
            LogPrintf("UDP: Got PONG message without PING from %s\n", it->first.ToString());
        else {
            LogPrintf("UDP: RTT to %s is %lf ms\n", it->first.ToString(), (GetTimeMicros() - nonceit->second) / 1000.0);
            state.ping_times.erase(nonceit);
        }
    }

    if (fBench) {
        std::chrono::steady_clock::time_point finish(std::chrono::steady_clock::now());
        if (to_millis_double(finish - start) > 1)
            LogPrintf("UDP: Packet took %lf ms to process\n", to_millis_double(finish - start));
    }
}

static void OpenUDPConnectionTo(const CService& addr, const UDPConnectionInfo& info);
static void timer_func(evutil_socket_t fd, short event, void* arg) {
    ProcessDownloadTimerEvents();

    UDPMessage msg;
    const int64_t now = GetTimeMillis();

    std::unique_lock<std::recursive_mutex> lock(cs_mapUDPNodes);

    {
        std::map<int64_t, std::pair<CService, uint64_t> >::iterator itend = nodesToRepeatDisconnect.upper_bound(now);
        for (std::map<int64_t, std::pair<CService, uint64_t> >::const_iterator it = nodesToRepeatDisconnect.begin(); it != itend; it++) {
            msg.header.msg_type = MSG_TYPE_DISCONNECT;
            SendMessage(msg, sizeof(UDPMessageHeader), it->second.first, it->second.second);
        }
        nodesToRepeatDisconnect.erase(nodesToRepeatDisconnect.begin(), itend);
    }

    for (std::map<CService, UDPConnectionState>::iterator it = mapUDPNodes.begin(); it != mapUDPNodes.end();) {
        boost::this_thread::interruption_point();

        UDPConnectionState& state = it->second;

        int64_t origLastSendTime = state.lastSendTime;

        if (state.lastRecvTime < now - 1000 * 60 * 10) {
            LogPrint("udpnet", "UDP: Peer %s timed out\n", it->first.ToString());
            it = send_and_disconnect(it); // Removes it from mapUDPNodes
            continue;
        }

        if (!(state.state & STATE_GOT_SYN_ACK) && origLastSendTime < now - 1000) {
            msg.header.msg_type = MSG_TYPE_SYN;
            msg.msg.longint = htole64(UDP_PROTOCOL_VERSION);
            SendMessage(msg, sizeof(UDPMessageHeader) + 8, it);
            state.lastSendTime = now;
        }

        if ((state.state & STATE_GOT_SYN) && origLastSendTime < now - 1000 * ((state.state & STATE_GOT_SYN_ACK) ? 10 : 1)) {
            msg.header.msg_type = MSG_TYPE_KEEPALIVE;
            SendMessage(msg, sizeof(UDPMessageHeader), it);
            state.lastSendTime = now;
        }

        if ((state.state & STATE_INIT_COMPLETE) == STATE_INIT_COMPLETE && state.lastPingTime < now - 1000 * 60 * 15) {
            uint64_t pingnonce = GetRand(std::numeric_limits<uint64_t>::max());
            msg.header.msg_type = MSG_TYPE_PING;
            msg.msg.longint = htole64(pingnonce);
            SendMessage(msg, sizeof(UDPMessageHeader) + 8, it);
            state.ping_times[pingnonce] = GetTimeMicros();
            state.lastPingTime = now;
        }

        for (std::map<uint64_t, int64_t>::iterator nonceit = state.ping_times.begin(); nonceit != state.ping_times.end();) {
            if (nonceit->second < (now - 5000) * 1000)
                nonceit = state.ping_times.erase(nonceit);
            else
                nonceit++;
        }

        it++;
    }

    for (const auto& conn : mapPersistentNodes) {
        if (!mapUDPNodes.count(conn.first)) {
            bool fWaitingOnDisconnect = false;
            for (const auto& repeatNode : nodesToRepeatDisconnect) {
                if (repeatNode.second.first == conn.first)
                    fWaitingOnDisconnect = true;
            }
            if (fWaitingOnDisconnect)
                continue;

            OpenUDPConnectionTo(conn.first, conn.second);
        }
    }
}

// ~10MB of outbound messages pending
#define PENDING_MESSAGES_BUFF_SIZE 10000
static std::mutex send_messages_mutex;
static std::atomic_bool send_messages_break(false);
static std::condition_variable send_messages_wake_cv;
static std::tuple<CService, UDPMessage, unsigned int, uint64_t> messagesPendingRingBuff[PENDING_MESSAGES_BUFF_SIZE];
static std::atomic<uint16_t> nextPendingMessage(0), nextUndefinedMessage(0);

static void SendMessage(const UDPMessage& msg, const unsigned int length, const CService& service, const uint64_t magic) {
    assert(length <= sizeof(UDPMessage));

    std::unique_lock<std::mutex> lock(send_messages_mutex);
    if (nextPendingMessage == (nextUndefinedMessage + 1) % PENDING_MESSAGES_BUFF_SIZE)
        return;

    std::tuple<CService, UDPMessage, unsigned int, uint64_t>& new_msg = messagesPendingRingBuff[nextUndefinedMessage];
    std::get<0>(new_msg) = service;
    memcpy(&std::get<1>(new_msg), &msg, length);
    std::get<2>(new_msg) = length;
    std::get<3>(new_msg) = magic;

    nextUndefinedMessage = (nextUndefinedMessage + 1) % PENDING_MESSAGES_BUFF_SIZE;

    lock.unlock();
    send_messages_wake_cv.notify_all();
}
static void SendMessage(const UDPMessage& msg, const unsigned int length, const std::map<CService, UDPConnectionState>::const_iterator& node) {
    return SendMessage(msg, length, node->first, node->second.connection.remote_magic);
}

static void do_send_messages() {
    static const size_t target_bytes_per_sec = 1024 * 1024 * 1024 / 8; // 1Gbps
    static const size_t max_buff_bytes = 50 * 1024; // Dont buffer more than 50K at a time

    static const size_t WRITE_OBJS_PER_CALL = max_buff_bytes / PACKET_SIZE;
    while (true) {
        if (nextUndefinedMessage == nextPendingMessage) {
            std::unique_lock<std::mutex> lock(send_messages_mutex);
            while (nextUndefinedMessage == nextPendingMessage && !send_messages_break)
                send_messages_wake_cv.wait(lock);
        }
        if (send_messages_break)
            return;

        std::chrono::steady_clock::time_point start(std::chrono::steady_clock::now());

        size_t i = 0;
        for (; i < WRITE_OBJS_PER_CALL && nextUndefinedMessage != nextPendingMessage; i++) {
            std::tuple<CService, UDPMessage, unsigned int, uint64_t>& msg = messagesPendingRingBuff[nextPendingMessage];

            sockaddr_in6 remoteaddr;
            memset(&remoteaddr, 0, sizeof(remoteaddr));
            remoteaddr.sin6_family = AF_INET6;
            assert(std::get<0>(msg).GetIn6Addr(&remoteaddr.sin6_addr));
            remoteaddr.sin6_port = htons(std::get<0>(msg).GetPort());

            FillChecksum(std::get<3>(msg), std::get<1>(msg), std::get<2>(msg));
            if (sendto(udp_sock, &std::get<1>(msg), std::get<2>(msg), 0, (sockaddr*)&remoteaddr, sizeof(remoteaddr)) != std::get<2>(msg)) {
                //TODO: Handle?
            }

            nextPendingMessage = (nextPendingMessage + 1) % PENDING_MESSAGES_BUFF_SIZE;
        }

        uint64_t sleep_time = 1000*1000 * PACKET_SIZE * i / target_bytes_per_sec;
        uint64_t run_time = std::chrono::duration_cast<std::chrono::duration<uint64_t, std::chrono::microseconds::period> >(std::chrono::steady_clock::now() - start).count();
        if (run_time < sleep_time)
            std::this_thread::sleep_for(std::chrono::microseconds(sleep_time - run_time));
    }
}

static void send_messages_flush_and_break() {
    send_messages_break = true;
    send_messages_wake_cv.notify_all();
}



/**
 * Public API follows
 */

unsigned short GetUDPInboundPort()
{
    return (unsigned short)(GetArg("-udpport", 0));
}

void GetUDPConnectionList(std::vector<UDPConnectionStats>& connections_list) {
    connections_list.clear();
    std::unique_lock<std::recursive_mutex> lock(cs_mapUDPNodes);
    for (const auto& node : mapUDPNodes)
        connections_list.push_back({node.first, node.second.connection.fTrusted, node.second.lastRecvTime});
}

static void OpenUDPConnectionTo(const CService& addr, const UDPConnectionInfo& info) {
    std::unique_lock<std::recursive_mutex> lock(cs_mapUDPNodes);
    assert(GetUDPInboundPort());

    std::pair<std::map<CService, UDPConnectionState>::iterator, bool> res = mapUDPNodes.insert(std::make_pair(addr, UDPConnectionState()));
    if (!res.second) {
        send_and_disconnect(res.first);
        res = mapUDPNodes.insert(std::make_pair(addr, UDPConnectionState()));
    }

    LogPrint("udpnet", "UDP: Initializing connection to %s...\n", addr.ToString());

    UDPConnectionState& state = res.first->second;
    state.connection = info;
    state.state = STATE_INIT;
    state.lastSendTime = 0;
    state.lastRecvTime = GetTimeMillis();
}

void OpenUDPConnectionTo(const CService& addr, uint64_t local_magic, uint64_t remote_magic, bool fUltimatelyTrusted) {
    OpenUDPConnectionTo(addr, {htole64(local_magic), htole64(remote_magic), fUltimatelyTrusted});
}

void OpenPersistentUDPConnectionTo(const CService& addr, uint64_t local_magic, uint64_t remote_magic, bool fUltimatelyTrusted) {
    std::unique_lock<std::recursive_mutex> lock(cs_mapUDPNodes);

    if (mapPersistentNodes.count(addr))
        return;

    UDPConnectionInfo info = {htole64(local_magic), htole64(remote_magic), fUltimatelyTrusted};
    mapPersistentNodes[addr] = info;
    OpenUDPConnectionTo(addr, info);
}
