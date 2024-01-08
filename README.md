# KyberKotlin _implements Kyber (ML-KEM)_

[Kyber](https://pq-crystals.org/kyber/index.shtml) is an IND-CCA2-secure key encapsulation mechanism (KEM), whose
security is based on the hardness of solving the learning-with-errors (LWE) problem over module lattices. Kyber is one 
of the finalists in the NIST post-quantum cryptography project. The submission lists three different parameter sets 
aiming at different security levels. Specifically, Kyber-512 aims at security roughly equivalent to AES-128, Kyber-768 
aims at security roughly equivalent to AES-192, and Kyber-1024 aims at security roughly equivalent to AES-256.

This project is heavily based on [kyberJCE](https://github.com/fisherstevenk/kyberJCE) by Steven Fisher. At the moment, this is about to change. Code is now
fully based on FIPS 203! In addition, parts of the code are based on other open-source implementations of CRYSTALS-Kyber
(ML-KEM).

## CAUTION

**_THIS PROJECT IS IN BUG FIXING PHASE. TESTED ON JAVA 17!_**

## Introduction

This is a 100% Kotlin/JVM implementation of ML-KEM.
It uses a Kotlin [hash](https://github.com/KotlinCrypto/hash) library in order to implement SHAKE and SHA3 within the library.
Unfortunately, due to support for X.509 encoding, this project had to use Bouncy Castle's bcutil-jdk18on library.

The goal for this project is to decouple from the aforementioned libraries that are not implemented in Kotlin.
This is in order to support Kotlin Multiplatform.

### Capabilities (For the pure Kotlin version | src/commonMain)
* Encapsulation (Unsuccessful)
* Decapsulation (Unsuccessful)

NOTE: THIS VERSION IS STILL IN DEVELOPMENT. PLEASE HELP ME FIX MANY OF MY MISTAKES.

### Capabilities (For the kyberJCE-based version | src/jvmMain)

* Public Key (Assymetric)
* Private Key (Assymetric)
* Cipher Text (For Shared Secret Key Generation)
* Multi-participant Shared Secret Key Generation _e.g. Bob and Alice (2 participants), or Bob, Alice, and Carol (3 participants), etc._
* Shared Secret Key (32 Bytes) _For Symmetric Encryption_

### Usage (For the kyberJCE-based version | src/jvmMain)

```Kotlin
val pairGen = KyberKeyPairGenerator() //Creates a key pair generator
pairGen.initialize(Kyber.KeySize.VARIANT_1024.length, SecureRandom()) //Variants are 512, 768, and 1024

val keyPairAlice = KyberKeyPair.wrap(pairGen.generateKeyPair()) //Generate keypair for Alice
val keyPairBob = KyberKeyPair.wrap(pairGen.generateKeyPair()) //Generate keypair for Alice

val bobAgreement = KyberKeyAgreement() //Create an agreement for Bob
bobAgreement.engineInit(keyPairBob.private) //Initialize Bob's agreement

//Bob receives Alice's Public Key and generates a Shared Secret Key (32 Bytes)
val bobSecretKey = bobAgreement.engineDoPhase(keyPairAlice.public, true)!! as KyberSharedSecretKey

val aliceAgreement = KyberKeyAgreement() //Create an agreement for Alice
aliceAgreement.engineInit(keyPairAlice.private) //Initialize Alice's agreement

//Alice receives the Cipher Text generated when Bob generated his Shared Secret Key
//Alice uses it to create her own Shared Secret key (32 Bytes)
val aliceSecretKey = aliceAgreement.engineDoPhase(bobAgreement.kyberCipherText!!, true)!! as KyberSharedSecretKey

//Bob's Secret Key
//[-83, 15, -110, -99, 24, -14, -125, -28, -53, 126, -18, 46, 93, -1, -83, 10, -124, 100, -45, -58, 55, -34, -107, -66, -105, 37, 35, -17, -24, -23, 28, -87]
//Alice's Secret Key
//[-83, 15, -110, -99, 24, -14, -125, -28, -53, 126, -18, 46, 93, -1, -83, 10, -124, 100, -45, -58, 55, -34, -107, -66, -105, 37, 35, -17, -24, -23, 28, -87]

//bobSecretKey == aliceSecretKey
```

In this example, **Bob** and **Alice** creates an **Agreement** that an eavesdropper would not be able to comprehend.
After generating the _Shared Secret Key_, they may communicate using a Symmetric Encryption algorithm _i.e. AES_.

### Intent

The intentions of this project are pure and transparent. Its goal is to decouple from the JVM and become a self-sufficient
Kotlin Multiplatform dependency. In other words, a PURE Kotlin implementation of ML-KEM in a lightweight format. This is
a stark difference compared to Bouncy Castle that supports most Encryption Algorithms and has a large data footprint.

At the 1.0.0 release, developers should be able to use this dependency if they want to support ML-KEM.

### Goal

To align with the NIST ML-KEM specification which is the designated Algorithm name for CRYSTALS-Kyber.
_**Digital security for all, everywhere, no matter who they are, or what they believe in.**_

### List of Bugs (For the kyberJCE-based version | src/jvmMain)

* Kyber variant 512 (Kyber-512) sometimes fail to create a matching Shared Secret Key.
* Have not been tested against other implementations. So far, it has been self-tested.
* DER(X.509) Encoding not tested or compared in any way.

### TODO List

* More unit tests (Please help).
* Optimize method names, attribute names, etc.
* Clean up code.
* Optimize code for Kotlin.
* Add references to FIPS 203.

### Why did I create this? _From Ron (Project Creator)_

I tried [kyberJCE](https://github.com/fisherstevenk/kyberJCE), the implementation of Steven Fisher. However, I encountered 
many bugs and problems whilst trying to make it work. I found his library to be nice, but it was full of inefficiencies that I thought I could fix. So far, I have made KotlinKyber
simple in its use. In the future, I want to use this library as a dependency for my future applications.

## Changelog

### v0.1.0

* Preparing for transition to debasing from kyberJCE.
* New codes directly derived from FIPS 203 ipd.
* NTT Zetas generator.
* Inverse EXP generator.
* Kotlin Multiplatform capabilities.

### v0.0.1

* It's working a little. Based on kyberJCE.

### References

* [CRYSTALS-Kyber Algorithm Specs v3.02](https://pq-crystals.org/kyber/data/kyber-specification-round3-20210804.pdf)
* [kyberJCE](https://github.com/fisherstevenk/kyberJCE)
* [kyber (C)](https://github.com/pq-crystals/kyber)
* [kyber (Rust)](https://github.com/Argyle-Software/kyber)
* [Montgomery Algorithm](https://www.ams.org/journals/mcom/1985-44-170/S0025-5718-1985-0777282-X/S0025-5718-1985-0777282-X.pdf)
* [Kyber-K2SO (Go)](https://github.com/symbolicsoft/kyber-k2so)
* [Kyber on ARM64](https://eprint.iacr.org/2021/561.pdf) _Explains the mysterious Qprime value 62209_

### License

```
Copyright 2023 Ron Lauren Hombre

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0
       
       and included as LICENSE.txt in this Project.

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
```

Although CRYSTALS-Kyber is Public Domain, this implementation is created through Hard Work by its Contributors.
Thus, the APACHE LICENSE v2.0 has been chosen.
