// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_MAIN_INTERNAL_H
#define BITCOIN_MAIN_INTERNAL_H

#include "main.h"

#include "blockencodings.h"

#include <list>
#include <vector>
#include <string>

using namespace std;

extern int64_t nTimeBestReceived;

class FeeFilterRounder;
extern FeeFilterRounder filterRounder;

struct IteratorComparator
{
    template<typename I>
    bool operator()(const I& a, const I& b)
    {
        return &(*a) < &(*b);
    }
};

struct COrphanTx {
    CTransaction tx;
    NodeId fromPeer;
    int64_t nTimeExpire;
};

extern map<uint256, COrphanTx> mapOrphanTransactions GUARDED_BY(cs_main);
extern map<COutPoint, set<map<uint256, COrphanTx>::iterator, IteratorComparator>> mapOrphanTransactionsByPrev GUARDED_BY(cs_main);

namespace main_internal {
    extern int nSyncStarted;
    extern boost::scoped_ptr<CRollingBloomFilter> recentRejects;
    extern uint256 hashRecentRejectsChainTip;

    /** Blocks that are in flight, and that are in the queue to be downloaded. Protected by cs_main. */
    struct QueuedBlock {
        uint256 hash;
        CBlockIndex* pindex;                                     //!< Optional.
        bool fValidatedHeaders;                                  //!< Whether this block has validated headers at the time of request.
        std::unique_ptr<PartiallyDownloadedBlock> partialBlock;  //!< Optional, used for CMPCTBLOCK downloads
    };
    extern map<uint256, pair<NodeId, list<QueuedBlock>::iterator> > mapBlocksInFlight;
    extern list<NodeId> lNodesAnnouncingHeaderAndIDs;
    extern int nPreferredDownload;
    extern int nPeersWithValidatedDownloads;

    typedef std::map<uint256, std::shared_ptr<const CTransaction>> MapRelay;
    extern MapRelay mapRelay;
    extern std::deque<std::pair<int64_t, MapRelay::iterator>> vRelayExpiration;
};

using namespace main_internal;

namespace main_internal {
    struct CBlockReject {
        unsigned char chRejectCode;
        string strRejectReason;
        uint256 hashBlock;
    };

    struct CNodeState {
        //! The peer's address
        CService address;
        //! Whether we have a fully established connection.
        bool fCurrentlyConnected;
        //! Accumulated misbehaviour score for this peer.
        int nMisbehavior;
        //! Whether this peer should be disconnected and banned (unless whitelisted).
        bool fShouldBan;
        //! String name of this peer (debugging/logging purposes).
        std::string name;
        //! List of asynchronously-determined block rejections to notify this peer about.
        std::vector<CBlockReject> rejects;
        //! The best known block we know this peer has announced.
        CBlockIndex *pindexBestKnownBlock;
        //! The hash of the last unknown block this peer has announced.
        uint256 hashLastUnknownBlock;
        //! The last full block we both have.
        CBlockIndex *pindexLastCommonBlock;
        //! The best header we have sent our peer.
        CBlockIndex *pindexBestHeaderSent;
        //! Whether we've started headers synchronization with this peer.
        bool fSyncStarted;
        //! Since when we're stalling block download progress (in microseconds), or 0.
        int64_t nStallingSince;
        list<QueuedBlock> vBlocksInFlight;
        //! When the first entry in vBlocksInFlight started downloading. Don't care when vBlocksInFlight is empty.
        int64_t nDownloadingSince;
        int nBlocksInFlight;
        int nBlocksInFlightValidHeaders;
        //! Whether we consider this a preferred download peer.
        bool fPreferredDownload;
        //! Whether this peer wants invs or headers (when possible) for block announcements.
        bool fPreferHeaders;
        //! Whether this peer wants invs or cmpctblocks (when possible) for block announcements.
        bool fPreferHeaderAndIDs;
        //! Whether this peer will send us cmpctblocks if we request them
        bool fProvidesHeaderAndIDs;

        CNodeState();
    };

    CNodeState *State(NodeId pnode);
    void UpdatePreferredDownload(CNode* node, CNodeState* state);
    bool MarkBlockAsReceived(const uint256& hash);
    bool MarkBlockAsInFlight(NodeId nodeid, const uint256& hash, const Consensus::Params& consensusParams, CBlockIndex *pindex = NULL, list<QueuedBlock>::iterator **pit = NULL);
    void ProcessBlockAvailability(NodeId nodeid);
    void UpdateBlockAvailability(NodeId nodeid, const uint256 &hash);
    bool CanDirectFetch(const Consensus::Params &consensusParams);
    void MaybeSetPeerAsAnnouncingHeaderAndIDs(const CNodeState* nodestate, CNode* pfrom);
    bool PeerHasHeader(CNodeState *state, CBlockIndex *pindex);
    void FindNextBlocksToDownload(NodeId nodeid, unsigned int count, std::vector<CBlockIndex*>& vBlocks, NodeId& nodeStaller);
};


bool AddOrphanTx(const CTransaction& tx, NodeId peer) EXCLUSIVE_LOCKS_REQUIRED(cs_main);
int EraseOrphanTx(uint256 hash) EXCLUSIVE_LOCKS_REQUIRED(cs_main);
unsigned int LimitOrphanTxSize(unsigned int nMaxOrphans) EXCLUSIVE_LOCKS_REQUIRED(cs_main);

enum FlushStateMode {
    FLUSH_STATE_NONE,
    FLUSH_STATE_IF_NEEDED,
    FLUSH_STATE_PERIODIC,
    FLUSH_STATE_ALWAYS
};

void NotifyHeaderTip();
bool FlushStateToDisk(CValidationState &state, FlushStateMode mode);
bool AcceptBlockHeader(const CBlockHeader& block, CValidationState& state, const CChainParams& chainparams, CBlockIndex** ppindex=NULL, bool* fNew=NULL);

void CheckBlockIndex(const Consensus::Params& consensusParams);

#endif // BITCOIN_MAIN_INTERNAL_H
