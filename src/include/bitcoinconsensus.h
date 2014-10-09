#ifndef H_BITCOIN_BITCOINSCRIPT
#define H_BITCOIN_BITCOINSCRIPT

// The following is stolen largely from https://gcc.gnu.org/wiki/Visibility
#if defined _WIN32 || defined __CYGWIN__
  #ifdef BUILDING_DLL
    #define EXPORT_SYMBOL __declspec(dllexport) // Note: actually gcc seems to also supports this syntax.
  #else
    #define EXPORT_SYMBOL __declspec(dllimport) // Note: actually gcc seems to also supports this syntax.
  #endif
#else
  #if __GNUC__ >= 4
    #define EXPORT_SYMBOL __attribute__ ((visibility ("default")))
  #else
    #define EXPORT_SYMBOL
  #endif
#endif

#ifdef __cplusplus
extern "C" {
#else
#include <stdbool.h>
#endif

/** Script verification flags */
enum
{
    bitcoinconsensus_SCRIPT_FLAGS_VERIFY_NONE      = 0,
    bitcoinconsensus_SCRIPT_FLAGS_VERIFY_P2SH      = (1U << 0), // evaluate P2SH (BIP16) subscripts
};

/// Returns true if the input nIn of the serialized transaction pointed to by
/// txTo correctly spends the scriptPubKey pointed to by scriptPubKey under
/// the additional constraints specified by flags.
bool bitcoinconsensus_verify_script(const unsigned char *scriptPubKey, const unsigned int scriptPubKeyLen,
                                    const unsigned char *txTo        , const unsigned int txToLen,
                                    const unsigned int nIn, const unsigned int flags) EXPORT_SYMBOL;

unsigned int bitcoinconsensus_version() EXPORT_SYMBOL;

#ifdef __cplusplus
} // extern "C"
#endif

#undef EXPORT_SYMBOL

#endif // H_BITCOIN_BITCOINSCRIPT
