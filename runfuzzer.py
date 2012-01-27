#!/usr/bin/env python
#
# Drive the bitcoin fuzzer via JSON-RPC to create
# lots of fuzzed transactions
#
# Example usage:  run_fuzzer.py --n=1000 --datadir=$HOME/testnet-box/1 --to-datadir=$HOME/testnet-box/2
# 
# DEPENDENCIES:  jsonrpc package from https://github.com/jgarzik/python-bitcoinrpc
#

from jsonrpc import ServiceProxy

def determine_db_dir():
  import os
  import os.path
  import platform
  if platform.system() == "Darwin":
    return os.path.expanduser("~/Library/Application Support/Bitcoin/")
  elif platform.system() == "Windows":
    return os.path.join(os.environ['APPDATA'], "Bitcoin")
  return os.path.expanduser("~/.bitcoin")

def read_bitcoinconfig(dbdir):
  import os
  from ConfigParser import SafeConfigParser

  class FakeSecHead(object):
    def __init__(self, fp):
      self.fp = fp
      self.sechead = '[all]\n'
    def readline(self):
      if self.sechead:
        try: return self.sechead
        finally: self.sechead = None
      else:
        s = self.fp.readline()
        if s.find('#') != -1:
          s = s[0:s.find('#')].strip() +"\n"
        return s

  config_parser = SafeConfigParser()
  config_parser.readfp(FakeSecHead(open(os.path.join(dbdir, "bitcoin.conf"))))
  return dict(config_parser.items("all"))
  

def main():
  import sys

  import optparse
  parser = optparse.OptionParser(usage="%prog [options]")
  parser.add_option("--n", dest="n", type="int", default=100,
                    help="Fuzz each sent n times (default: %default)")
  parser.add_option("--datadir", dest="datadir", default=None,
                    help="datadir for fuzzing bitcoind (defaults to bitcoin default)")
  parser.add_option("--to-datadir", dest="to_datadir", default=None,
                    help="datadir for bitcoind to receive coins (defaults to same as fuzzer)")
  parser.add_option("--quiet", dest="quiet", default=False,
                    action="store_true",
                    help="Don't print progress to stdout")
  parser.add_option("--sendonly", dest="sendonly", default=False,
                    action="store_true",
                    help="Just send the bitcoins, don't fuzz")
  (options, args) = parser.parse_args()

  if options.datadir is None:
    db_dir = determine_db_dir()
  else:
    db_dir = options.datadir

  conf = read_bitcoinconfig(db_dir)
  if not 'rpcport' in conf: conf['rpcport'] = 8332

  connect = "http://%s:%s@127.0.0.1:%s"%(conf['rpcuser'], conf['rpcpassword'], conf['rpcport'])
  bitcoind = ServiceProxy(connect)

  if options.to_datadir is not None:
    to_conf = read_bitcoinconfig(options.to_datadir)
    if not 'rpcport' in to_conf: to_conf['rpcport'] = 8332
    to_connect = "http://%s:%s@127.0.0.1:%s"%(to_conf['rpcuser'], to_conf['rpcpassword'], to_conf['rpcport'])
    to_bitcoind = ServiceProxy(to_connect)
  else:
    to_bitcoind = bitcoind

  i = bitcoind.getinfo()
  if not i['testnet']:
    print "Fuzzer only works on -testnet bitcoinds"
    sys.exit(0)

  if not options.quiet:
    print("Generating new addresses...")

  # Get 10 new addresses/public keys:
  addresses = []
  pubkeys = []
  for i in xrange(10):
    addr = to_bitcoind.getnewaddress()
    addresses.append(addr)
    pubkeys.append(to_bitcoind.validateaddress(addr)['pubkey'])

  # ... and use them to generate a bunch of multisig addresses:
  for i in xrange(5):
    addresses.append(to_bitcoind.addmultisigaddress(1, [ pubkeys[i] ]))
    addresses.append(to_bitcoind.addmultisigaddress(1, [ pubkeys[i], pubkeys[i+1] ]))
    addresses.append(to_bitcoind.addmultisigaddress(1, [ pubkeys[i], pubkeys[i+1], pubkeys[i+2] ]))
    addresses.append(to_bitcoind.addmultisigaddress(2, [ pubkeys[i+2], pubkeys[i+1] ]))
    addresses.append(to_bitcoind.addmultisigaddress(2, [ pubkeys[i+3], pubkeys[i+4], pubkeys[i+5] ]))
    addresses.append(to_bitcoind.addmultisigaddress(3, [ pubkeys[i+3], pubkeys[i+4], pubkeys[i+5] ]))

  print("Creating send transactions...")

  import random;
  random.shuffle(addresses)

  txids = []
  for addr in addresses:
    to_addr = random.choice(addresses)
    txids.append(bitcoind.sendtoaddress(to_addr, 0.001+random.random()/100.0))

  if options.sendonly:
    sys.exit(0)

  print("Fuzzing each %d times"%(options.n,))
  from time import sleep
  for i in xrange(options.n):
    for tx in txids:
      bitcoind.relayfuzzed(tx, i)
    if i > 0 and i%100 == 0:
      sleep(0.2)
      if not options.quiet:
        print("..."+str(i))


if __name__ == '__main__':
    main()
