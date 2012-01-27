Hacked version of Bitcoin that adds a "relayfuzzed" command.
Note: this only works on the testnet.

USING THIS CODE
---------------

First, create one or more transactions using the send* RPC commands, and
remember their transaction IDs. This version of bitcoin is modified so
'original' wallet transactions are not announced to the network.

Then, you can generate as many "fuzzed" variations as you like using the
relayfuzzed command, which takes a transaction ID and an integer to seed
a random number generator.

Example usage from a bash prompt:

    # Run two bitcoind's that talk to each other:
    alias bc1="./bitcoind -datadir=testnet-box/1"
    alias bc2="./bitcoind -datadir=testnet-box/2"
    bc1 -daemon
    bc2 -daemon

    # Now fuzz a send-to-self:
    TXID=$(bc1 -testnet sendtoaddress $(bc1 getnewaddress) 0.01)
    for i in {1..100}; do bc1 relayfuzzed $TXID $i; done

The result should be a long list of fuzzed transaction ids, almost all of
which are actually bad, invalid transactions. And a lot of
"ConnectInputs failed" in testnet-box/2/testnet/debug.log

See runfuzzer.py for an example fuzzing/stress-testing tool.


THINGS TO BE AWARE OF
---------------------

You will trigger the denial-of-service-prevention code using this. If
you are running a "testnet-in-a-box" setup
(see https://sourceforge.net/projects/bitcoin/files/Bitcoin/testnet-in-a-box/)
then you don't have to worry, nodes running on localhost don't disconnect
each other for bad behavior. Otherwise, you can run bitcoind with
-banscore=999999 to avoid being disconnected.

Running the code being tested under Valgrind or Purify or another
memory-corruption detection tool is a good idea.


Types of "high-level" fuzzing done:
-----------------------------------
* Insert random opcodes at the front of the transactions's scriptSig(s)


Types of "low-level" fuzzing done:
----------------------------------
* Change bit in one of the transaction's bytes

* Delete one or more bytes

* Insert one or more random bytes


TODO:
-----

* Generate mostly-random scriptSig/scriptPubkey pairs that validate,
  and generate pairs/chains of valid transactions that spend them.


