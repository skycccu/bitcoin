// Copyright (c) 2016 Matt Corallo
// Unlike the rest of Bitcoin Core, this file is
// distributed under the Affero General Public License (AGPL v3)

#if defined(HAVE_CONFIG_H)
#include "config/bitcoin-config.h"
#endif

#include "udpnet.h"

#include "chainparams.h"
#include "consensus/validation.h"
#include "compat/endian.h"
#include "hash.h"
#include "main.h"
#include "net.h"
#include "primitives/block.h"
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

struct __attribute__((packed)) UDPMessage {
    UDPMessageHeader header;
    union __attribute__((packed)) {
        unsigned char message[MAX_UDP_MESSAGE_LENGTH + 1];
        uint64_t longint;
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
};
#define PROTOCOL_VERSION_MIN(ver) (((ver) >> 16) & 0xffff)
#define PROTOCOL_VERSION_CUR(ver) (((ver) >>  0) & 0xffff)
#define PROTOCOL_VERSION_FLAGS(ver) (((ver) >> 32) & 0xffffffff)

static std::recursive_mutex cs_mapUDPNodes;
static std::map<CService, UDPConnectionState> mapUDPNodes;
static std::map<int64_t, std::pair<CService, uint64_t> > nodesToRepeatDisconnect;
static std::map<CService, UDPConnectionInfo> mapPersistentNodes;


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

void UDPRelayBlock(const CBlock& block) {
    LOCK(cs_mapUDPNodes);
    if (mapUDPNodes.empty())
        return;

    //TODO compress block

    for (std::map<CService, UDPConnectionState>::iterator it = mapUDPNodes.begin(); it != mapUDPNodes.end(); it++) {
        UDPConnectionState& state = it->second;
        if ((state.state & STATE_INIT_COMPLETE) != STATE_INIT_COMPLETE)
            continue;

        //TODO: SendMessages
    }
}

static void BlockRecvInit() {

}

static void BlockRecvShutdown() {

}

static bool HandleBlockMessage(UDPMessage& msg, size_t length, const CService& node, UDPConnectionState& state) {
    return true;
}

static void ProcessDownloadTimerEvents() {

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
            return send_and_disconnect(it);
        }

        state.protocolVersion = le64toh(msg.msg.longint);
        if (PROTOCOL_VERSION_MIN(state.protocolVersion) > 1) {
            LogPrintf("UDP: Got min protocol version we didnt understand (%u:%u) from %s\n", PROTOCOL_VERSION_MIN(state.protocolVersion), PROTOCOL_VERSION_CUR(state.protocolVersion), it->first.ToString());
            return send_and_disconnect(it);
        }

        if (!(state.state & STATE_GOT_SYN))
            state.state |= STATE_GOT_SYN;
    } else if (msg.header.msg_type == MSG_TYPE_KEEPALIVE) {
        if (res != sizeof(UDPMessageHeader)) {
            LogPrintf("UDP: Got invalidly-sized KEEPALIVE message from %s\n", it->first.ToString());
            return send_and_disconnect(it);
        }
        if ((state.state & STATE_INIT_COMPLETE) != STATE_INIT_COMPLETE)
            LogPrint("udpnet", "UDP: Successfully connected to %s!\n", it->first.ToString());

        // If we get a SYNACK without a SYN, that probably means we were restarted, but the other side wasn't
        // ...this means the other side thinks we're fully connected, so just switch to that mode
        state.state |= STATE_GOT_SYN_ACK | STATE_GOT_SYN;
    } else if (msg.header.msg_type == MSG_TYPE_DISCONNECT) {
        LogPrintf("UDP: Got disconnect message from %s\n", it->first.ToString());
        return silent_disconnect(it);
    }

    if (!(state.state & STATE_INIT_COMPLETE))
        return;

    if (msg.header.msg_type == MSG_TYPE_BLOCK_HEADER || msg.header.msg_type == MSG_TYPE_BLOCK_CONTENTS) {
        if (!HandleBlockMessage(msg, res, it->first, it->second))
            return send_and_disconnect(it);
    } else if (msg.header.msg_type == MSG_TYPE_PING) {
        if (res != sizeof(UDPMessageHeader) + 8) {
            LogPrintf("UDP: Got invalidly-sized PING message from %s\n", it->first.ToString());
            return send_and_disconnect(it);
        }

        msg.header.msg_type = MSG_TYPE_PONG;
        SendMessage(msg, sizeof(UDPMessageHeader) + 8, it);
    } else if (msg.header.msg_type == MSG_TYPE_PONG) {
        if (res != sizeof(UDPMessageHeader) + 8) {
            LogPrintf("UDP: Got invalidly-sized PONG message from %s\n", it->first.ToString());
            return send_and_disconnect(it);
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
