Zeek Package To Detect Cryptocurrency (Bitcoin) Mining
======================================================

This script/package for Zeek can detect Bitcoin, Litecoin, PPCoin, or
other cryptocurrency mining traffic that uses `getwork
<https://en.bitcoin.it/wiki/Getwork>`_, `getblocktemplate
<https://en.bitcoin.it/wiki/Getblocktemplate>`_, or `Stratum
<http://mining.bitcoin.cz/stratum-mining/>`_ mining protocols over TCP
or HTTP.  Note that the module cannot currently detect the Bitcoin P2P
protocol, which is different from the mining protocols.

See mining.zeek for more details on how it works.
