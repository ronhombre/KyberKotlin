# KyberKotlin _implements ML-KEM (CRYSTALS-Kyber)_

[Kyber](https://pq-crystals.org/kyber/index.shtml) is an IND-CCA2-secure key encapsulation mechanism (KEM), whose
security is based on the hardness of solving the learning-with-errors (LWE) problem over module lattices. Kyber is one 
of the finalists in the NIST post-quantum cryptography project. The submission lists three different parameter sets 
aiming at different security levels. Specifically, Kyber-512 aims at security roughly equivalent to AES-128, Kyber-768 
aims at security roughly equivalent to AES-192, and Kyber-1024 aims at security roughly equivalent to AES-256.

This project is semi-fully based on FIPS 203! (Some seemingly unintended changes were reverted i.e. transposition of
two matrices.)

## CAUTION

**_THIS PROJECT IS IN OPTIMIZATION PHASE. TESTED ON JAVA 17!_**

## Introduction

This is a 100% Kotlin Multiplatform implementation of ML-KEM.
It uses a Kotlin [hash](https://github.com/KotlinCrypto/hash) library in order to implement SHAKE and SHA3 within the library.

## Benchmarks (Tested on a Ryzen 7 5800X)

| Variant | Generation | Encapsulation | Decapsulation |
|---------|------------|---------------|---------------|
| 512     | 12332      | 8683          | 5446.8        |
| 768     | 16027.6    | 12783.8       | 9783.2        |
| 1024    | 21640.4    | 18687.8       | 15753.2       |
| ML-KEM  | (in ms)    | (in ms)       | (in ms)       |

Ran with JVM 17 5 times and averaged. Lower is better.
Code is in [Benchmark.kt](https://github.com/ronhombre/KyberKotlin/blob/master/src/commonTest/kotlin/asia/hombre/kyber/Benchmark.kt)

This benchmark is for performance tracking through the development.

## Capabilities
* Encapsulation (512, 768, 1024)
* Decapsulation (512, 768, 1024)

NOTE: THIS VERSION IS STILL IN DEVELOPMENT.

### Usage

```Kotlin
import asia.hombre.kyber.KeyAgreement
import asia.hombre.kyber.KyberKeyPairGenerator
import asia.hombre.kyber.KyberParameter

//Generate keys
//This would be done in their own systems
val keyPairAlice = KyberKeyPairGenerator().generate(KyberParameter.ML_KEM_512)
val keyPairBob = KyberKeyPairGenerator().generate(KyberParameter.ML_KEM_512)

val agreementAlice = KeyAgreement(keyPairAlice)

//Bob sends his encapsulation key to Alice
//Alice uses it to encapsulate a Secret Key
val cipherTextAlice = agreementAlice.encapsulate(keyPairBob.encapsulationKey)

val agreementBob = KeyAgreement(keyPairBob)

//Alice sends the Cipher Text to Bob
//Bob decapsulates the Cipher Text
val secretKeyBob = agreementBob.decapsulate(cipherTextAlice.cipherText)

//Alice generated the Secret Key
println("Gen: " + cipherTextAlice.secretKey.joinToString(", "))
//Bob decapsulated the same Secret Key
println("Rec: " + secretKeyBob.joinToString(", "))

//Bob's Secret Key
//[91, 119, -51, 71, -106, 30, -66, 47, 53, -7, -119, -38, -78, 61, -27, 44, -15, -47, -115, -92, -26, -120, 124, -17, -121, 83, 0, -57, -71, 118, 2, -31]
//Alice's Secret Key
//[91, 119, -51, 71, -106, 30, -66, 47, 53, -7, -119, -38, -78, 61, -27, 44, -15, -47, -115, -92, -26, -120, 124, -17, -121, 83, 0, -57, -71, 118, 2, -31]

//bobSecretKey == aliceSecretKey
```

In this example, **Bob** and **Alice** creates an **Agreement** that an eavesdropper would not be able to comprehend even
if it is intercepted. After generating the _Shared Secret Key_, they may communicate using a Symmetric Encryption
algorithm _i.e. AES_.

### Intent

The intentions of this project are pure and transparent. Its goal is to decouple from the JVM and become a self-sufficient
Kotlin Multiplatform dependency. In other words, a PURE Kotlin implementation of ML-KEM in a lightweight format. This is
a stark difference compared to Bouncy Castle that supports most Encryption Algorithms and has a large data footprint.

At the 1.0.0 release, developers should be able to use this dependency if they want to support ML-KEM.

### Goal

To align with the NIST ML-KEM specification which is the designated Algorithm name for CRYSTALS-Kyber.
_**Digital security for all, everywhere, no matter who they are, or what they believe in.**_

### TODO List

* More unit tests (Please help).
* Optimize method names, attribute names, etc.
* Clean up code.
* Optimize code for Kotlin.
* Add references to FIPS 203.
* Add classes for jvmMain.

### Why did I create this? _From Ron (Project Creator)_

I tried [kyberJCE](https://github.com/fisherstevenk/kyberJCE), the implementation of Steven Fisher. However, I encountered 
many bugs and problems whilst trying to make it work. I found his library to be nice, but it was full of inefficiencies
that I thought I could fix. So far, I have made KyberKotlin simple in its use. In the future, I want to use this library
as a dependency for my future applications.

## Special Thanks

* IAmDerek for guiding me in NTT.
* grhkm for helping me with implementing NTT.
* versusdkp for providing me a link for intermediates for testing.
* FiloSottile's mlkem768 which gave me clues to fix bugs in my implementation.
* Steven Fisher's kyberJCE which helped me run my first tests and use one of its algorithms.
* and others from CryptoHack community!

### References

* [NIST FIPS 203 ipd](https://csrc.nist.gov/pubs/fips/203/ipd)
* [CRYSTALS-Kyber Algorithm Specs v3.02](https://pq-crystals.org/kyber/data/kyber-specification-round3-20210804.pdf)
* [kyberJCE](https://github.com/fisherstevenk/kyberJCE)
* [CCTestVectors](https://github.com/C2SP/CCTV/)
* [mlkem768](https://github.com/FiloSottile/mlkem768)
* [kyber (C)](https://github.com/pq-crystals/kyber)
* [kyber (Rust)](https://github.com/Argyle-Software/kyber)
* [Montgomery Algorithm](https://www.ams.org/journals/mcom/1985-44-170/S0025-5718-1985-0777282-X/S0025-5718-1985-0777282-X.pdf)
* [Kyber-K2SO (Go)](https://github.com/symbolicsoft/kyber-k2so)
* [Kyber on ARM64](https://eprint.iacr.org/2021/561.pdf) _Explains the mysterious Qinv value 62209_

### License

```
Copyright 2024 Ron Lauren Hombre

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


## Changelog

### v0.2.4

* Cleaned up and formatted code.
* Optimized minor code.
* Made KyberParameter the central basis for the lengths of ciphertext, encaps key, and decaps key.
* Gradle jvmJar.
* Added warning for use of internal/SecureRandom.

### v0.2.3

* Cleaned up code.
* Added exceptions for encapsulation and decapsulation.

### v0.2.2

* Added parameter values for lengths of cipher, encaps key, and decaps key.
* Added copyright notices.

### v0.2.1

* Code optimizations.
* Benchmarks are added.
* Reorganized Generators.

### v0.2.0

* Encapsulation and Decapsulation succeeds.
* New test cases for algorithms.
* Removed old code based from kyberJCE.

### v0.1.0

* Preparing for transition to debasing from kyberJCE.
* New codes directly derived from FIPS 203 ipd.
* NTT Zetas generator.
* Inverse EXP generator.
* Kotlin Multiplatform capabilities.

### v0.0.1

* It's working a little. Based on kyberJCE.
