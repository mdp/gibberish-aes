# Gibberish AES
## A Javascript library for OpenSSL compatible AES encryption

##Deprecation Notice

This library is a quite old, and uses an older and non-authenticated cipher mode, CBC. There are better and more frequently maintained alternatives. Here are a couple that I would recommend:

- [LibSodium](https://github.com/jedisct1/libsodium) is becoming a widely adopted library with a variety of languages supported including Ruby and JS. Example of a similar API in LibSodium.js - [mdp/gibberish-libsodium](https://github.com/mdp/gibberish-libsodium)
- [Stanford's Javascript Crypto Library](https://github.com/bitwiseshiftleft/sjcl) features OCB mode AES encryption along with authentication. Supported on most modern browsers and in node.

----

Copyright: Mark Percival 2008 - <http://markpercival.us>  
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

In Javascript

    GibberishAES.enc("Made with Gibberish\n", "password");
    // Outputs: "U2FsdGVkX1+21O5RB08bavFTq7Yq/gChmXrO3f00tvJaT55A5pPvqw0zFVnHSW1o"

On the command line

    echo "U2FsdGVkX1+21O5RB08bavFTq7Yq/gChmXrO3f00tvJaT55A5pPvqw0zFVnHSW1o" | openssl enc -d -aes-256-cbc -a -k password -md md5


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

It only supports CBC AES encryption mode, and it's built to be compatible with OpenSSL.
