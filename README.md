# ECC Encryption
 
Java and JavaScript examples of mutual Elliptic Curve Encryption (ECC). 

AES symmetric key is generated using Elliptic-curve Diffie–Hellman(ECDH) key agreement. 

Java part of this example uses Bouncy Caste cryptography library. Public and Private keys are saved in JKS keystore. Public Key in X509 format with a self-signed 
certificate. 

Web part uses SubtleCrypto API. Public and private keys are saved and loaded from IndexedDB.  


# Dependencies

- [SubtleCrypto](https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto)

- [BouncyCaste](https://www.bouncycastle.org/java.html)


# Resources

- [https://en.wikipedia.org/wiki/Elliptic-curve_Diffie%E2%80%93Hellman](https://en.wikipedia.org/wiki/Elliptic-curve_Diffie%E2%80%93Hellman)

- [Bouncy Caste Java API](https://www.bouncycastle.org/docs/docs1.5on/index.html)

- [How to save keys in local JKS storage](http://tutorials.jenkov.com/java-cryptography/keystore.html)

- [SubtleCrypto examples](https://github.com/mdn/dom-examples/tree/master/web-crypto)
