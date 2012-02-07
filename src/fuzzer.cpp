//
// Code for "fuzzing" transactions, to test implementations' network protocol handling
//
#include "util.h"
#include "serialize.h"
#include "main.h"
#include "wallet.h"
#include "net.h"
#include "fuzzer.h"

#include <stdlib.h>
#include <boost/math/distributions/exponential.hpp>

// Return integer from [0...n)
static int
R(int n)
{
    unsigned int random = rand();
    unsigned int max_custom_rand = RAND_MAX;
    while (random > max_custom_rand - ((max_custom_rand+1) % n))
    {
        // make sure random values are equally probablistic across all possible return values
        while (n > max_custom_rand+1)
        {
            random = random * RAND_MAX + rand();
            max_custom_rand = max_custom_rand * RAND_MAX + RAND_MAX;
        }
    }
    return random % n;
}

// Return integer from [0..n),
// but with values near 0 exponentially more likely
static int
RExp(int n)
{
    boost::math::exponential_distribution<int> d(2.0);
    double v = boost::math::quantile(d, R(INT_MAX)) * n / 5.0;

    if (v > n-1)
        return n-1;
    return int(v);
}

// Return n pseudo-random bytes
static std::vector<unsigned char>
Bytes(int n)
{
    std::vector<unsigned char> result;
    for (int i = 0; i < n; i++)
        result[i] = R(256);
    return result;
}

// Return vector of n pretty-likely-to-be-valid Script opcodes:
static std::vector<unsigned char>
OpCodes(int n)
{
    std::vector<unsigned char> result;
    for (int i = 0; i < n; i++)
    {
        result.push_back(static_cast<unsigned char>(R(OP_NOP10+1)));
    }
    return result;
}


//
// Add random bytes to one of tx's scriptSig's.
// This will sometimes be harmless, just changing the
// transaction hash, and sometimes make the transaction
// invalid.
//
void
TweakScriptSig(CTransaction& tx)
{
    int whichTxIn = R(tx.vin.size());

    int nToInsert = RExp(1000)+1;
    CScript& scriptSig = tx.vin[whichTxIn].scriptSig;
    std::vector<unsigned char> toInsert;
    toInsert = OpCodes(nToInsert);

    scriptSig.insert(scriptSig.begin(), toInsert.begin(), toInsert.end());
}

// Change one bit in s:
void
ToggleBit(CDataStream& s)
{
    int byte = R(s.size());
    unsigned char mask = 1 << R(8);
    s[byte] = s[byte]^mask;
}

// Change one byte in s:
void
ChangeByte(CDataStream& s)
{
    int byte = R(s.size());
    unsigned char bits = 1+R(255); // 1-255
    s[byte] = s[byte]^bits;
}

// Insert n random bytes into s, at a random location:
void
InsertBytes(CDataStream& s, int n)
{
    CDataStream s2(Bytes(n));
    int where = R(s.size());
    s.insert(s.begin()+where, s2.begin(), s2.end());
}

// Erase n random bytes, at a random location:
void
EraseBytes(CDataStream& s, int n)
{
    if (n > s.size()) n = s.size();
    int where = R(s.size()-n);
    s.erase(s.begin()+where, s.begin()+where+n);
}

void
FuzzTransaction(const CTransaction& tx, const unsigned int& fuzzSeed, CDataStream& fuzzedDataRet)
{
    srand(fuzzSeed);

    CTransaction tweaked = tx;
    TweakScriptSig(tweaked);

    // Mess with another input 10% of the time:
    if (R(10) == 0)
        TweakScriptSig(tweaked);

    fuzzedDataRet << tweaked;

    // 10% chance of each of these:
    if (R(10) == 0)
        ToggleBit(fuzzedDataRet);
    if (R(10) == 0)
        ChangeByte(fuzzedDataRet);
    if (R(10) == 0)
        InsertBytes(fuzzedDataRet, RExp(500));
    if (R(10) == 0)
        EraseBytes(fuzzedDataRet, R(fuzzedDataRet.size()));
}

void
FuzzRelayTransaction(const CTransaction& tx)
{
    // No fuzzing on main net for now:
    if (!fTestNet)
    {
        printf("ERROR: fuzzing enabled only on testnet\n");
        return;
    }

    CDataStream ss(SER_NETWORK);

    static bool fInitialized = false;
    static uint64_t fuzzSeed = 0;

    if (!fInitialized)
    {
        fuzzSeed = GetArg("-fuzzseed", GetTime());
        fInitialized = true;
    }
    else
        ++fuzzSeed;

    FuzzTransaction(tx, fuzzSeed, ss);

    uint256 hash = Hash(ss.begin(), ss.end());

    printf("Relaying fuzzed tx %s\n", hash.ToString().c_str());
    printf(" (wallet tx: %s fuzzSeed: %u)\n", tx.GetHash().ToString().c_str(), fuzzSeed);

    if (fDebug)
    {
        printf("fuzzed hex:\n");
        PrintHex(ss.begin(), ss.end());
    }

    RelayMessage(CInv(MSG_TX, hash), ss);
}
