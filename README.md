libswift
========

The multiparty transport protocol.

## Description ##
This is Libswift (aka BitTorrent at the transport layer).
Differently from TCP, the protocol does not use the ordered data stream abstraction.
Effectively, it splits a file into 1KB packets and sends them around.
The secret sauce is Merkle hash trees and binmaps.
 
Requires libevent-2.0.17 or higher.

See [doc/index.html][1] for marketing stuff, ideas and rants,
[doc/draft-ietf-ppsp-peer-protocol-00.txt][2] for the drafr protocol specification,
and `*.cpp` files for the actual code.

[1]: http://htmlpreview.github.com/?https://github.com/libswift/libswift/blob/master/doc/index.html
[2]: https://raw.github.com/libswift/libswift/master/doc/draft-ietf-ppsp-peer-protocol-00.txt

## Usage ##

`swift.cpp` is the main exec file; it may be run as e.g.
    
    $ ./swift -t node300.das2.ewi.tudelft.nl:20000 -h \
    d1502706c46779d361a1d562a10da0a45c4c40e5 -f \
    trailer.ogg
        
...to retrieve video and save it to a file.

Alternatively, you might play with the HTTP gateway, the preliminary
version. First, run the seeder-tracker: 

    $ ./swift -f ~/Downloads/big_buck_bunny_480p_stereo.ogg -l 0.0.0.0:20000
    Root hash: 7c462ad1d980ba44ab4b819e29004eb0bf6e6d5f

...then you may try running the swift-HTTP gateway...

    $ ./swift -t 127.0.0.1:20000 -g 0.0.0.0:8080 -w

...and finally you may point your browser at the gateway...

    http://127.0.0.1:8080/7c462ad1d980ba44ab4b819e29004eb0bf6e6d5f
        
If you use an HTML5 browser (Chrome preferred),
you are likely to see the bunny trailer at this point...