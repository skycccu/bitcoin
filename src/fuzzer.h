//
// Code for "fuzzing" transactions, to test implementations' network protocol handling
//
#ifndef BITCOIN_FUZZER_H
#define BITCOIN_FUZZER_H

#include "main.h"

extern void FuzzTransaction(const CTransaction& tx, const unsigned int& fuzzSeed, CDataStream& fuzzedDataRet);
extern void FuzzRelayTransaction(const CTransaction& tx);

#endif
