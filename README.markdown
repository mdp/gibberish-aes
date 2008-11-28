# Gibberish AES
## A Javascript library for OpenSSL compatible CBC encryption

----

Copyright: Mark Percival 2008 - <http://mpercival.com>  
License: MIT

Thanks to :

  - Josh Davis - [http://www.josh-davis.org/ecmaScrypt](http://www.josh-davis.org/ecmaScrypt)
  - Alex Boussinet [alex.boussinet@gmail.com](mailto:alex.boussinet@gmail.com)
  - Chris Veness - [http://www.movable-type.co.uk/scripts/aes.html](http://www.movable-type.co.uk/scripts/aes.html)
  - Michel I. Gallant - [http://www.jensign.com/](http://www.jensign.com/)
  - Kristof Neirynck - [http://github.com/Crydust](http://github.com/Crydust) Fixes for IE7, YUI compression, JSLINT errors


### Usage
        // GibberishAES.enc(string, password)
        // Defaults to 256 bit encryption
        enc = GibberishAES.enc("This sentence is super secret", "ultra-strong-password");
        alert(enc);
        GibberishAES.dec(enc, "ultra-strong-password");

        // Now change size to 128 bits
        GibberishAES.size(128);
        enc = GibberishAES.enc("This sentence is not so secret", "1234");
        GibberishAES.dec(enc, "1234");

        // And finally 192 bits
        GibberishAES.size(192);
        enc = GibberishAES.enc("I can't decide!!!", "whatever");
        GibberishAES.dec(enc, "whatever");

#### OpenSSL Interop

        // In Jascascript
        GibberishAES.enc("Made with Gibberish\n", "password");
        // Outputs: "U2FsdGVkX1+21O5RB08bavFTq7Yq/gChmXrO3f00tvJaT55A5pPvqw0zFVnHSW1o"
        
        # On the command line
        echo "U2FsdGVkX1+21O5RB08bavFTq7Yq/gChmXrO3f00tvJaT55A5pPvqw0zFVnHSW1o" | openssl enc -d -aes-256-cbc -a -k password

### Design Factors
I built this library for [G.ibberish.com](http://g.ibberish.com), which heavily influenced it's design.
It only supports CBC AES encryption mode, and it's built to be compatible with one
of the most popular AES libraries available, OpenSSL.

Although there's some things I dislike about OpenSSL, it's a commonly used and very capable
library that's been open source for quite some time, and has received [FIPS certification][1]
from NIST.

One of my primary issues with other AES libraries is the lack of support for OpenSSL. I
don't think one can expect users to trust a library that's not compatible with a standard
like OpenSSL. It's outside the range of many users to audit encryption code, and while
compatibility doesn't ensure 100% compliance(especially with asymmetric encryption), one 
can come pretty close with a symmetric algorithm like AES where the only difference is 
how OpenSSL picks its random 8 byte salt.

I built Gibberish to output its encrypted data in an identical format to OpenSSL, with
an 8 byte salted PBE, and a Base64 encoding output. This should allow anyone using the
library to interoperate with OpenSSL with the least amount of work.

The size of this library is under 25k when it's compressed and I feel that's adequate for
most uses. Although I used lookup tables for Galois fields, the cost of the size
increase was well offset by the more than 10 fold increase in speed. I think 10k extra
is a small price to pay for a speed increase like that.

I've also done my best to keep the library clean and encapsulated. I want this library
to be capable of being dropped into nearly any website and function without hindering
other libraries in use. The downside to this is that it grew with the addition of its
own Base64 library and MD5 hashing algorithm. I'm not sure that at 25k it really matters.
It's a pretty specific library built to handle a specific task, I doubt anyone using it
will sweat the extra size.

### Testing package
Open up the test directory and you'll find an HTML file that allows you to verify it's
working with your browser, computing FIPS test vectors correctly, handling UTF-8 properly,
and compatible with OpenSSL.

The test script does require JQuery(included), but the
basic GibberishAES does not. It's only included to make testing easier.

### Todo
I'm still cleaning up the code, but functionally it's finished and working. I've included a minified
version of the library weighing in at just shy of 23k.

I'll be happy to accept bug fixes or code updates, however I don't plan updating this library to
support more than the basic AES CBC encryption. This falls outside of the scope of this project;
I chose CBC because it's considered the most secure and popular form of AES encryption, and I
don't feel the need to offer support for other modes.

### SlowAES

In the process of making this library, I was contacted by Josh Davis, the writer of emcaScrypt,
in regards to helping out with the project [SlowAES][2].

It's an important project, because while there are a number of
good AES programs out there, few are compatible with OpenSSL. A lot
of this is due to the lack of documentation on how OpenSSL handles its
encryption, and I would recommend that anyone thinking about writing their own AES
library should check it out. One of my goals is to with SlowAES is to build some better
documentation on how OpenSSL handles AES encryption.

[1]: http://en.wikipedia.org/wiki/OpenSSL#FIPS_140-2_compliance "FIPS Compliance"
[2]: http://code.google.com/p/slowaes "SlowAES Project Page"