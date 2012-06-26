#include "blockstore.h"
#include "util.h"
#include "net.h"
#include "main.h"

void CBlockStore::CallbackCommitBlock(const CBlock& block, const uint256& hash)
{
    {
        LOCK(cs_mapGetBlockIndexWaits);
        std::map<uint256, CSemaphore*>::iterator it = mapGetBlockIndexWaits.find(hash);
        if (it != mapGetBlockIndexWaits.end() && it->second != NULL)
            it->second->post_all();
    }
    LOCK(sigtable.cs_sigCommitBlock);
    sigtable.sigCommitBlock(block);
}

void CBlockStore::SubmitCallbackFinishEmitBlock(CBlock& block, CNode* pNodeDoS)
{
    unsigned int nQueueSize;
    {
        LOCK(cs_callbacks);
        nQueueSize = queueFinishEmitBlockCallbacks.size();
    }
    while (nQueueSize >= GetArg("-blockbuffersize", 20) && fProcessCallbacks)
    {
        Sleep(20);
        LOCK(cs_callbacks);
        nQueueSize = queueFinishEmitBlockCallbacks.size();
    }

    if (pNodeDoS) pNodeDoS->AddRef();

    LOCK(cs_callbacks);
    queueFinishEmitBlockCallbacks.push(std::make_pair(new CBlock(block), pNodeDoS));
    sem_callbacks.post();
}

void CBlockStore::StopProcessCallbacks()
{
    {
        LOCK(cs_callbacks);
        fProcessCallbacks = false;
        sem_callbacks.post();
        for (int i = 0; i < nProcessingCallbacks; i++)
            sem_SetValidCalls.post();
    }
    while (nProcessingCallbacks > 0)
        Sleep(20);
}

void CBlockStore::ProcessCallbacks()
{
    {
        LOCK(cs_callbacks);
        if (!fProcessCallbacks)
            return;
        nProcessingCallbacks++;
    }

    loop
    {
        std::pair<CBlock*, CNode*> callback;
        sem_callbacks.wait();
        if (fProcessCallbacks)
        {
            LOCK(cs_callbacks);
            assert(queueFinishEmitBlockCallbacks.size() > 0);
            callback = queueFinishEmitBlockCallbacks.front();
            queueFinishEmitBlockCallbacks.pop();
        }
        else
        {
            LOCK(cs_callbacks);
            nProcessingCallbacks--;
            return;
        }

        FinishEmitBlock(*(callback.first), callback.second);
        delete callback.first;
        if (callback.second) callback.second->Release();
    }
}

void CBlockStoreProcessCallbacks(void* parg)
{
    ((CBlockStore*)parg)->ProcessCallbacks();
}

void CBlockStore::ProcessSetValidCallbacks()
{
    {
        LOCK(cs_callbacks);
        if (!fProcessCallbacks)
            return;
        nProcessingCallbacks++;
    }

    loop
    {
        boost::tuple<boost::function <bool()>*, bool*, MapPrevTx*> callback;
        sem_SetValidCalls.wait();
        if (fProcessCallbacks)
        {
            LOCK(cs_queueSetValidCalls);
            assert(queueSetValidCalls.size() > 0);
            callback = queueSetValidCalls.front();
            queueSetValidCalls.pop();
        }
        else
        {
            LOCK(cs_callbacks);
            nProcessingCallbacks--;
            return;
        }
        if (!(*(boost::tuples::get<0>(callback)))())
            *(boost::tuples::get<1>(callback)) = false;
        delete boost::tuples::get<0>(callback);
        delete boost::tuples::get<2>(callback);

        sem_SetValidCallsDone.post();
    }
}

void CBlockStoreProcessSetValidCallbacks(void* parg)
{
    ((CBlockStore*)parg)->ProcessSetValidCallbacks();
}

CBlockStore::CBlockStore() : sem_callbacks(0), fProcessCallbacks(true), nProcessingCallbacks(0), sem_SetValidCalls(0), sem_SetValidCallsDone(0)
{
    if (!CreateThread(CBlockStoreProcessCallbacks, this))
        throw std::runtime_error("Couldn't create callback threads");
    for (int i = 0; i < GetArg("-sigverifyconcurrency", boost::thread::hardware_concurrency()); i++)
        if (!CreateThread(CBlockStoreProcessSetValidCallbacks, this))
            throw std::runtime_error("Couldn't create callback threads");
}
