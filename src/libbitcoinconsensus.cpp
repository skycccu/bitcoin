#include "bitcoinconsensus.h"
#include "version.h"
#include "core.h"
#include "script/interpreter.h"

bool bitcoinconsensus_verify_script(const unsigned char *scriptPubKey, const unsigned int scriptPubKeyLen,
                                    const unsigned char *txTo        , const unsigned int txToLen,
                                    const unsigned int nIn, const unsigned int flags)
{
    try {
        if (!scriptPubKey || !txTo || !scriptPubKeyLen || !txToLen)
            return false;

        CTransaction tx;
        CDataStream stream(std::vector<unsigned char>(txTo, txTo + txToLen), SER_NETWORK, PROTOCOL_VERSION);
        stream >> tx;

        if (nIn >= tx.vin.size())
            return false;

        return VerifyScript(tx.vin[nIn].scriptSig, CScript(scriptPubKey, scriptPubKey + scriptPubKeyLen), flags, SignatureChecker(tx, nIn));
    } catch (std::exception &e) {
        return false; // Error deserializing
    }
}

unsigned int bitcoinconsensus_version()
{
    return 0;
}
