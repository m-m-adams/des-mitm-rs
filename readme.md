Currently this is just a rewrite in rust but it's approximately 20 times faster than my original go implementation (although it took much longer to write)

TODO - improve key generation to take a seed and chain "weakhashes" to generate more keys and then check on the fly if a collision has been found yet