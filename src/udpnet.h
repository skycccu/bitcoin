// Copyright (c) 2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_UDPNET_H
#define BITCOIN_UDPNET_H

#include <stdint.h>
#include <vector>

#include "netbase.h"

class CBlock;

unsigned short GetUDPInboundPort();
bool InitializeUDPConnections();
void StopUDPConnections();

// fUltimatelyTrusted means you trust them (ie whitelist) and ALL OF THEIR SUBSEQUENT WHITELISTED PEERS
void OpenUDPConnectionTo(const CService& remote_addr, uint64_t local_magic, uint64_t remote_magic, bool fUltimatelyTrusted);
void OpenPersistentUDPConnectionTo(const CService& remote_addr, uint64_t local_magic, uint64_t remote_magic, bool fUltimatelyTrusted);

struct UDPConnectionStats {
    CService remote_addr;
    bool fUltimatelyTrusted;
    int64_t lastRecvTime;
};
void GetUDPConnectionList(std::vector<UDPConnectionStats>& connections_list);

void UDPRelayBlock(const CBlock& block);

#endif
