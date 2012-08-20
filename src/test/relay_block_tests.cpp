#include <boost/test/unit_test.hpp>
#include "main.h"

using namespace std;

BOOST_AUTO_TEST_SUITE(bloom_tests)

BOOST_AUTO_TEST_CASE(relay_block)
{
    // Random real block (0000000000010ac94a7f73848a32a33238e34162df6b4118e6e37fa2ae986e72)
    // With two non-coinbase transactions
    CBlock block;
    CDataStream stream(ParseHex("0100000072c229f4ea2252a08d7359de887c16a2f61340b56e37a88274ac01000000000098d1dcc4eddd630f1a198f075189406a42990c42a812ef625f0e5a6300d199702a5f1b4d4c86041bf9eaedf60301000000010000000000000000000000000000000000000000000000000000000000000000ffffffff07044c86041b012cffffffff0100f2052a010000004341047225e10079c83e10a5b227050007d08262b2f5ed1f0389e8bebc93ba07a47930ed7ada3ecf80bb19c36bb313bcd9cb9f5bc33fb6c40b50c09fddf19c3ff1a408ac000000000100000001c8df58609d7530860a7f4fe512b60119cc6033754902f74ec13ed1f7456e0e5a000000008a47304402206361ba282b5f406f26fbbdba558092c37378d99f82b4ecf74689055d7dc78e40022031ad22e06f4345fc17aba3d2f3d765396941ee00b0cf514b5a07c030094d20b1014104a9b73ee9a65cb5a124e6f6dbc45989c71af984ccd95e67a0bbee49c32253fea26e6fa2f1f24e40e885c014aff1e3ed3cf28ddf8bff7441643aebe006312b4f88ffffffff02404b4c00000000001976a914ff601b914a32980ca054631a90446bd3cb37b19488ac80c1cd01080000001976a914bc0c286fb20ae4e2d90dd89248244015003e6b1688ac000000000100000001fe91b17b0952077075716e5fdb9ec4b5a49a13ccc2488d86df40d1ea88cd5ec7010000008c493046022100ffe159aba7c740f30d21babadcb61980ec9de6b4fbbaa6a767aaec746a3e94f0022100c7f4622cb7bb45ebb0aa110ebeaa5f58467391b322bf5d5534fba0f30c75e3e3014104e2077da583e0d4e66f68d9e303dd2b6e517a9ecdc65d28606920923403c43c511d2c64c918938030e71dcb52260c848c51fe2ca28990be2d16ba7d310bc04b0cffffffff0200baba32030000001976a914acbe63a3509b23bb2d1d5710c73709a6f62a09a888ac404b4c00000000001976a914aa1578cc6d4affac28f1e6d4058df535bdf16eaf88ac00000000"), SER_NETWORK, PROTOCOL_VERSION);
    stream >> block;

    CRelayBlock relayBlock(block);
    CDataStream relayStream(SER_NETWORK, PROTOCOL_VERSION);
    relayStream << relayBlock;

    vector<unsigned char> vch = ParseHex("0100000072c229f4ea2252a08d7359de887c16a2f61340b56e37a88274ac01000000000098d1dcc4eddd630f1a198f075189406a42990c42a812ef625f0e5a6300d199702a5f1b4d4c86041bf9eaedf601000000010000000000000000000000000000000000000000000000000000000000000000ffffffff07044c86041b012cffffffff0100f2052a010000004341047225e10079c83e10a5b227050007d08262b2f5ed1f0389e8bebc93ba07a47930ed7ada3ecf80bb19c36bb313bcd9cb9f5bc33fb6c40b50c09fddf19c3ff1a408ac000000000250715d22d6eb848e34f85c4339915148d7be61a9f70f32f5278a361e47ebf3d3e3f059e91e62e6f047952890bf2ad001a5ef78a5ba3497b3433e8e37b5f6bc7c");
    vector<char> expected(vch.size());

    for (unsigned int i = 0; i < vch.size(); i++)
        expected[i] = (char)vch[i];

    BOOST_CHECK_EQUAL_COLLECTIONS(expected.begin(), expected.end(), relayStream.begin(), relayStream.end());

    // Keep the stream from clearing after last read
    relayStream.write("\0", 1);

    CRelayBlock relayBlockDeserialized;
    relayStream >> relayBlockDeserialized;

    BOOST_CHECK(relayBlock.GetBlockHash() == relayBlockDeserialized.GetBlockHash() &&
                relayBlock.GetBlockHash() == block.GetHash());

    std::set<uint256> setMissingTxes;
    relayBlockDeserialized.GetMissingTransactions(setMissingTxes);
    BOOST_CHECK(setMissingTxes.size() == 2);
    BOOST_CHECK(setMissingTxes.count(uint256("0xd3f3eb471e368a27f5320ff7a961bed748519139435cf8348e84ebd6225d7150")));
    BOOST_CHECK(setMissingTxes.count(uint256("0x7cbcf6b5378e3e43b39734baa578efa501d02abf90289547f0e6621ee959f0e3")));

    relayBlockDeserialized.ProvideTransaction(block.vtx[1]);
    CBlock blockRet;
    BOOST_CHECK(!relayBlockDeserialized.GetBlock(blockRet));
    relayBlockDeserialized.ProvideTransaction(block.vtx[2]);
    BOOST_CHECK(relayBlockDeserialized.GetBlock(blockRet));
    BOOST_CHECK(blockRet.GetHash() == block.GetHash());
    BOOST_CHECK(blockRet.vtx.size() == block.vtx.size() && block.vtx.size() == 3);
    BOOST_CHECK(blockRet.vtx[0].GetHash() == block.vtx[0].GetHash() &&
                blockRet.vtx[1].GetHash() == block.vtx[1].GetHash() &&
                blockRet.vtx[2].GetHash() == block.vtx[2].GetHash());
    BOOST_CHECK(blockRet.CheckBlock());

    CTxMemPool mempool;
    mempool.addUnchecked(block.vtx[1].GetHash(), block.vtx[1]);

    BOOST_CHECK(relayStream.Rewind(expected.size()));
    CRelayBlock relayBlockDeserialized2;
    relayStream >> relayBlockDeserialized2;

    CBlock blockRet2;
    BOOST_CHECK(!relayBlockDeserialized2.GetBlock(blockRet2));
    BOOST_CHECK(!relayBlockDeserialized2.FillFromMemPool(mempool));
    BOOST_CHECK(!relayBlockDeserialized2.GetBlock(blockRet2));

    mempool.addUnchecked(block.vtx[2].GetHash(), block.vtx[2]);
    BOOST_CHECK(relayBlockDeserialized2.FillFromMemPool(mempool));
    BOOST_CHECK(relayBlockDeserialized2.GetBlock(blockRet2));
    BOOST_CHECK(blockRet2.GetHash() == block.GetHash() && blockRet2.CheckBlock());
}

BOOST_AUTO_TEST_CASE(relay_block_pool)
{
    // Random real block (0000000000010ac94a7f73848a32a33238e34162df6b4118e6e37fa2ae986e72)
    // With 2 non-coinbase transactions
    CRelayBlock block;
    CDataStream stream(ParseHex("0100000072c229f4ea2252a08d7359de887c16a2f61340b56e37a88274ac01000000000098d1dcc4eddd630f1a198f075189406a42990c42a812ef625f0e5a6300d199702a5f1b4d4c86041bf9eaedf601000000010000000000000000000000000000000000000000000000000000000000000000ffffffff07044c86041b012cffffffff0100f2052a010000004341047225e10079c83e10a5b227050007d08262b2f5ed1f0389e8bebc93ba07a47930ed7ada3ecf80bb19c36bb313bcd9cb9f5bc33fb6c40b50c09fddf19c3ff1a408ac000000000250715d22d6eb848e34f85c4339915148d7be61a9f70f32f5278a361e47ebf3d3e3f059e91e62e6f047952890bf2ad001a5ef78a5ba3497b3433e8e37b5f6bc7c"), SER_NETWORK, PROTOCOL_VERSION);
    stream >> block;

    CNode from(INVALID_SOCKET, CAddress());

    CPendingRelayBlockPool mempoolBlocks;
    std::vector<CInv> missingInvs;
    BOOST_CHECK(!mempoolBlocks.AddBlock(block, &from, missingInvs));
    BOOST_CHECK(from.GetRefCount() == 1);
    BOOST_CHECK(missingInvs.size() == 2 &&
                std::find(missingInvs.begin(), missingInvs.end(), CInv(MSG_TX, uint256("0xd3f3eb471e368a27f5320ff7a961bed748519139435cf8348e84ebd6225d7150"))) != missingInvs.end() &&
                std::find(missingInvs.begin(), missingInvs.end(), CInv(MSG_TX, uint256("0x7cbcf6b5378e3e43b39734baa578efa501d02abf90289547f0e6621ee959f0e3"))) != missingInvs.end());

    CTransaction tx;
    BOOST_CHECK(!mempoolBlocks.ProvideTransaction(tx, tx.GetHash()));

    CDataStream streamTx(ParseHex("0100000001fe91b17b0952077075716e5fdb9ec4b5a49a13ccc2488d86df40d1ea88cd5ec7010000008c493046022100ffe159aba7c740f30d21babadcb61980ec9de6b4fbbaa6a767aaec746a3e94f0022100c7f4622cb7bb45ebb0aa110ebeaa5f58467391b322bf5d5534fba0f30c75e3e3014104e2077da583e0d4e66f68d9e303dd2b6e517a9ecdc65d28606920923403c43c511d2c64c918938030e71dcb52260c848c51fe2ca28990be2d16ba7d310bc04b0cffffffff0200baba32030000001976a914acbe63a3509b23bb2d1d5710c73709a6f62a09a888ac404b4c00000000001976a914aa1578cc6d4affac28f1e6d4058df535bdf16eaf88ac00000000"), SER_NETWORK, PROTOCOL_VERSION);
    streamTx >> tx;
    BOOST_CHECK(mempoolBlocks.ProvideTransaction(tx, tx.GetHash()));

    BOOST_CHECK(!mempoolBlocks.ProcessBlocks());

    CDataStream streamTx2(ParseHex("0100000001c8df58609d7530860a7f4fe512b60119cc6033754902f74ec13ed1f7456e0e5a000000008a47304402206361ba282b5f406f26fbbdba558092c37378d99f82b4ecf74689055d7dc78e40022031ad22e06f4345fc17aba3d2f3d765396941ee00b0cf514b5a07c030094d20b1014104a9b73ee9a65cb5a124e6f6dbc45989c71af984ccd95e67a0bbee49c32253fea26e6fa2f1f24e40e885c014aff1e3ed3cf28ddf8bff7441643aebe006312b4f88ffffffff02404b4c00000000001976a914ff601b914a32980ca054631a90446bd3cb37b19488ac80c1cd01080000001976a914bc0c286fb20ae4e2d90dd89248244015003e6b1688ac00000000"), SER_NETWORK, PROTOCOL_VERSION);
    streamTx2 >> tx;
    BOOST_CHECK(mempoolBlocks.ProvideTransaction(tx, tx.GetHash()));

    BOOST_CHECK(mempoolBlocks.ProcessBlocks(false));
    BOOST_CHECK(from.GetRefCount() == 0);
}

BOOST_AUTO_TEST_SUITE_END()
