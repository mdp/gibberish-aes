# Gibberish AES
## A Javascript library for OpenSSL compatible AES encryption

----

Copyright: Mark Percival 2008 - <http://markpercival.us>  
License: MIT

Thanks to :

- Josh Davis - [http://www.josh-davis.org/ecmaScrypt](http://www.josh-davis.org/ecmaScrypt)
- Alex Boussinet [alex.boussinet@gmail.com](mailto:alex.boussinet@gmail.com)
- Chris Veness - [http://www.movable-type.co.uk/scripts/aes.html](http://www.movable-type.co.uk/scripts/aes.html)
- Michel I. Gallant - [http://www.jensign.com/](http://www.jensign.com/)
- Kristof Neirynck - [http://github.com/Crydust](http://github.com/Crydust) Fixes for IE7, YUI compression, JSLINT errors

### Also see:

Gibberish is meant to be compatible for OpenSSL AES on the command line. There are other Javascript crypto libraries out there that may be better suite for your needs. One of the most popular and actively maintained libraries is
[Stanford's Javascript Crypto Library](https://github.com/bitwiseshiftleft/sjcl). It supports more cipher block modes, along with authentication.


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

  In Javascript
  
        GibberishAES.enc("Made with Gibberish\n", "password");
        // Outputs: "U2FsdGVkX1+21O5RB08bavFTq7Yq/gChmXrO3f00tvJaT55A5pPvqw0zFVnHSW1o"
        
  On the command line
  
        echo "U2FsdGVkX1+21O5RB08bavFTq7Yq/gChmXrO3f00tvJaT55A5pPvqw0zFVnHSW1o" | openssl enc -d -aes-256-cbc -a -k password


### Requirements

None.

The library is fully encapsulated, you should be able to drop it into nearly any website.
The downside to this is that it grew with the addition of its
own Base64 library and MD5 hashing algorithm.

### Tests

[Click here][2] to run the test package in your browser.

The test script does require JQuery(included), but the
basic GibberishAES does not.

### Design Factors

It only supports CBC AES encryption mode, and it's built to be compatible with one
of the most popular AES libraries available, OpenSSL. It also passed the [FIPS certification][1]
from NIST.

One of my primary issues with other AES libraries is the lack of support for OpenSSL.
One can't expect users to trust a library that's not compatible with a standard
like OpenSSL. It's outside the range of many users to audit encryption code, and while
compatibility doesn't ensure 100% compliance(especially with asymmetric encryption), one 
can come pretty close with a symmetric algorithm like AES where the only difference is 
how OpenSSL picks its random 8 byte salt.

The size of this library is under 25k when it's compressed and I feel that's adequate for
most uses. Although I used lookup tables for Galois fields, the cost of the size
increase was well offset by the more than 10 fold increase in speed.


[1]: http://en.wikipedia.org/wiki/OpenSSL#FIPS_140-2_compliance "FIPS Compliance"
[2]: http://mdp.github.com/gibberish-aes/gibberish-aes-test.html "Gibberish Tests"
