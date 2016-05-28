// Copyright (c) 2009-2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "rpc/server.h"

#include "hash.h"
#include "utilstrencodings.h"
#include "udpnet.h"
#include "netbase.h"

#include <univalue.h>

using namespace std;

UniValue getudppeerinfo(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 0)
        throw runtime_error(
            "getudppeerinfo\n"
            "\nReturns data about each connected UDP peer as a json array of objects.\n"
            "\nResult:\n"
            "[\n"
            "  {\n"
            "    \"addr\":\"host:port\",        (string)  The ip address and port of the peer\n"
            "    \"lastrecv\": ttt,             (numeric) The time in seconds since epoch (Jan 1 1970 GMT) of the last receive\n"
            "    \"ultimatetrust\": true/false  (boolean) Whether this peer, and all of its peers, are trusted\n"
            "  }\n"
            "  ,...\n"
            "]\n"
            "\nExamples:\n"
            + HelpExampleCli("getudppeerinfo", "")
            + HelpExampleRpc("getudppeerinfo", "")
        );

    vector<UDPConnectionStats> vstats;
    GetUDPConnectionList(vstats);

    UniValue ret(UniValue::VARR);

    for (const UDPConnectionStats& stats : vstats) {
        UniValue obj(UniValue::VOBJ);
        obj.push_back(Pair("addr", stats.remote_addr.ToString()));
        obj.push_back(Pair("lastrecv", stats.lastRecvTime));
        obj.push_back(Pair("whitelisted", stats.fUltimatelyTrusted));

        ret.push_back(obj);
    }

    return ret;
}

UniValue addudpnode(const UniValue& params, bool fHelp)
{
    string strCommand;
    if (params.size() == 5)
        strCommand = params[4].get_str();
    if (fHelp || params.size() != 5 ||
        (strCommand != "onetry" && strCommand != "add"))
        throw runtime_error(
            "addudpnode \"node\" \"local_magic\" \"remote_magic\" ultimately_trusted \"add|onetry\"\n"
            "\nAttempts add a node to the UDP addnode list.\n"
            "Or try a connection to a UDP node once.\n"
            "\nArguments:\n"
            "1. \"node\"                (string, required)  The node IP:port\n"
            "2. \"local_magic\"         (string, required)  Our magic secret value for this connection (should be a secure, random string)\n"
            "3. \"remote_magic\"        (string, required)  The node's magic secret value (should be a secure, random string)\n"
            "4. \"ultimately_trusted\"  (boolean, required) Whether to trust this peer, and all of its trusted UDP peers, recursively\n"
            "5. \"command\"             (string, required)  'add' to add a persistent connection or 'onetry' to try a connection to the node once\n"
            "\nExamples:\n"
            + HelpExampleCli("addnode", "\"192.168.0.6:8333\" \"onetry\"")
            + HelpExampleRpc("addnode", "\"192.168.0.6:8333\", \"onetry\"")
        );

    string strNode = params[0].get_str();

    CService addr;
    if (!Lookup(strNode.c_str(), addr, -1, true) || !addr.IsValid())
        throw JSONRPCError(RPC_INVALID_PARAMS, "Error: Failed to lookup node, address not valid or port missing.");

    string local_pass = params[1].get_str();
    uint64_t local_magic = Hash(&local_pass[0], &local_pass[0] + local_pass.size()).GetUint64(0);
    string remote_pass = params[2].get_str();
    uint64_t remote_magic = Hash(&remote_pass[0], &remote_pass[0] + local_pass.size()).GetUint64(0);

    bool fTrust = params[3].get_bool();

    if (strCommand == "onetry")
        OpenUDPConnectionTo(addr, local_magic, remote_magic, fTrust);
    else if (strCommand == "add")
        OpenPersistentUDPConnectionTo(addr, local_magic, remote_magic, fTrust);

    return NullUniValue;
}





static const CRPCCommand commands[] =
{ //  category              name                      actor (function)         okSafeMode
  //  --------------------- ------------------------  -----------------------  ----------
    { "udpnetwork",         "getudppeerinfo",         &getudppeerinfo,         true  },
    { "udpnetwork",         "addudpnode",             &addudpnode,             true  },
    //{ "udpnetwork",         "getaddednodeinfo",       &getaddednodeinfo,       true  },
};

void RegisterUDPNetRPCCommands(CRPCTable &tableRPC)
{
    for (unsigned int vcidx = 0; vcidx < ARRAYLEN(commands); vcidx++)
        tableRPC.appendCommand(commands[vcidx].name, &commands[vcidx]);
}
