# KyberKotlin _implements ML-KEM (CRYSTALS-Kyber)_
_**Digital security for all, everywhere, no matter who they are, or what they believe in.**_

[![CodeQL master](https://github.com/ronhombre/KyberKotlin/actions/workflows/codeql.yml/badge.svg)](https://github.com/ronhombre/KyberKotlin/actions/workflows/codeql.yml)
[![Maven Central](https://img.shields.io/maven-central/v/asia.hombre/kyber.svg)](https://search.maven.org/#search%7Cga%7C1%7Cg%3A%22asia.hombre%22)
[![GitHub license](https://img.shields.io/badge/license-Apache%20License%202.0-blue.svg?style=flat)](https://www.apache.org/licenses/LICENSE-2.0)
![Gradle](https://img.shields.io/badge/Gradle-02303A.svg?style=for-the-badge&logo=Gradle&logoColor=white)
![Kotlin](https://img.shields.io/badge/kotlin-%237F52FF.svg?style=for-the-badge&logo=kotlin&logoColor=white)
![Java](https://img.shields.io/badge/java-%23ED8B00.svg?style=for-the-badge&logo=openjdk&logoColor=white)
![C#](https://img.shields.io/badge/c%23-%23239120.svg?style=for-the-badge&logo=csharp&logoColor=white)
![JS](https://img.shields.io/badge/JavaScript-F7DF1E?style=for-the-badge&logo=javascript&logoColor=black)


[Kyber](https://pq-crystals.org/kyber/index.shtml) is an IND-CCA2-secure key encapsulation mechanism (KEM), whose
security is based on the hardness of solving the learning-with-errors (LWE) problem over module lattices. Kyber is one 
of the finalists in the NIST post-quantum cryptography project. The submission lists three different parameter sets 
aiming at different security levels. Specifically, Kyber-512 aims at security roughly equivalent to AES-128, Kyber-768 
aims at security roughly equivalent to AES-192, and Kyber-1024 aims at security roughly equivalent to AES-256.

This project is semi-fully based on FIPS 203! (Some seemingly unintended changes were reverted i.e. transposition of
two matrices.)

## Introduction

This is a 100% Kotlin Multiplatform implementation of ML-KEM.
It depends on Kotlin [sha3](https://github.com/KotlinCrypto/hash), [keccak](https://github.com/KotlinCrypto/sponges),
and [secure-random](https://github.com/KotlinCrypto/secure-random) libraries in order to implement SHA3, SHAKE, and
Secure Random within the library.

> [!WARNING]
> KyberKotlin is in **ALPHA**. At this stage, we are confident it can withstand production. However, it has not been battle-tested yet. Mock tests are on the way.

### Intent

At the 1.0.0 release, developers from various platforms should be able to use this dependency if they want to support ML-KEM.

## Benchmarks (Tested on a Ryzen 7 5800X; Windows 11)

| Variant | Generation              | Encapsulation           | Decapsulation           |
|---------|-------------------------|-------------------------|-------------------------|
| 512     | 5840.625   (43% Faster) | 5529.0     (62% Faster) | 5545.1875  (79% Faster) |
| 768     | 10098.4375 (34% Faster) | 10249.5    (47% Faster) | 10423.0625 (62% Faster) |
| 1024    | 16513.8125 (29% Faster) | 17222.125  (35% Faster) | 17501.125  (49% Faster) |
| ML-KEM  | (in ms)                 | (in ms)                 | (in ms)                 |

JVM: Coretto 1.8, Count: 10000, Iterations: 5 (Average), Relative to 'standard' branch as of Feb. 14, 2024.

Code is in [JVMBenchmark.kt](https://github.com/ronhombre/KyberKotlin/blob/master/src/jvmTest/kotlin/asia/hombre/kyber/tests/JVMBenchmark.kt)

This benchmark is for performance tracking through the development.

> [!NOTE]
> This master branch is faster than the standard branch due to optimizations.

### Summary
* Variant 512 takes **0.58ms** to Generate a Keypair
* Variant 768 takes **1ms** to Generate a Keypair
* Variant 1024 takes **1.65ms** to Generate a Keypair
* Variant 512 takes **0.55ms** to Encapsulate
* Variant 768 takes **1ms** to Encapsulate
* Variant 1024 takes **1.7ms** to Encapsulate
* Variant 512 takes **0.55ms** to Decapsulate
* Variant 768 takes **1ms** to Decapsulate
* Variant 1024 takes **1.75ms** to Decapsulate

## Capabilities
* Key Generation (512, 768, 1024)
* Encapsulation (512, 768, 1024)
* Decapsulation (512, 768, 1024)
* Convert to or from HEX, BASE64, and BYTES.

## Supported & Tested Platforms
* JVM (Java, Kotlin)
* Javascript (NPM) _Slower by 2-3x_
* Native (C#)

## KDocs Documentation
* [Website](https://kyber.hombre.asia)

## JVM Installation

### Maven with Gradle Kotlin DSL

```Kotlin
dependencies {
    implementation("asia.hombre:kyber:0.4.10")
}
```

### JAR with Gradle Kotlin DSL

Get a jar from [releases](https://github.com/ronhombre/KyberKotlin/releases) and copy it into `libs/` of your JVM project.

```Kotlin
dependencies {
    implementation(fileTree(mapOf("dir" to "libs", "include" to listOf("*.jar"))))
}
```

[More](https://central.sonatype.com/artifact/asia.hombre/kyber/overview) installation methods

## JS NPM Installation
```
npm i kyberkotlin
```

## Native C# Installation

### DLL Import

Get it from [releases](https://github.com/ronhombre/KyberKotlin/releases) and copy it into your C# project.

## Usage

### With JVM

Kotlin
```Kotlin
import asia.hombre.kyber.KyberAgreement
import asia.hombre.kyber.KyberKeyGenerator
import asia.hombre.kyber.KyberParameter

//Generate keys
//This would be done in their own systems
val keyPairAlice = KyberKeyGenerator.generate(KyberParameter.ML_KEM_512)
val keyPairBob = KyberKeyGenerator.generate(KyberParameter.ML_KEM_512)

val agreementAlice = KyberAgreement(keyPairAlice)

//Bob sends his encapsulation key to Alice
//Alice uses it to encapsulate a Secret Key
val cipherTextAlice = agreementAlice.encapsulate(keyPairBob.encapsulationKey)

val agreementBob = KyberAgreement(keyPairBob)

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

//secretKeyBob == cipherTextAlice.secretKey
```

Java

```Java
import asia.hombre.kyber.KyberKeyGenerator;
import asia.hombre.kyber.KyberKEMKeyPair;
import asia.hombre.kyber.KyberParameter;
import asia.hombre.kyber.KyberAgreement;
import asia.hombre.kyber.KyberEncapsulationResult;

//Generate keys
//This would be done in their own systems
KyberKEMKeyPair keyPairAlice = KyberKeyGenerator.generate(KyberParameter.ML_KEM_512);
KyberKEMKeyPair keyPairBob = KyberKeyGenerator.generate(KyberParameter.ML_KEM_512);

KyberAgreement agreementAlice = new KyberAgreement(keyPairAlice);

//Bob sends his encapsulation key to Alice
//Alice uses it to encapsulate a Secret Key
KyberEncapsulationResult encapsResult = agreementAlice.encapsulate(keyPairBob.getEncapsulationKey());

KyberAgreement agreementBob = new KyberAgreement(keyPairBob);

//Alice sends the Cipher Text to Bob
//Bob decapsulates the Cipher Text
byte[] decapsSecretKey = agreementBob.decapsulate(encapsResult.getCipherText());

//Alice generated the Secret Key
System.out.println(Arrays.toString(encapsResult.getSecretKey()));
//Bob decapsulated the same Secret Key
System.out.println(Arrays.toString(decapsSecretKey));

//Bob's Secret Key
//[91, 119, -51, 71, -106, 30, -66, 47, 53, -7, -119, -38, -78, 61, -27, 44, -15, -47, -115, -92, -26, -120, 124, -17, -121, 83, 0, -57, -71, 118, 2, -31]
//Alice's Secret Key
//[91, 119, -51, 71, -106, 30, -66, 47, 53, -7, -119, -38, -78, 61, -27, 44, -15, -47, -115, -92, -26, -120, 124, -17, -121, 83, 0, -57, -71, 118, 2, -31]


//encapsResult.getSecretKey() == decapsSecretKey
```

In this example, **Bob** and **Alice** creates an **Agreement** that an eavesdropper would not be able to comprehend even
if it is intercepted. After generating the _Shared Secret Key_, they may communicate using a Symmetric Encryption
algorithm _i.e. AES_.

### With Javascript

```javascript
const { KyberParameter, KyberKeyGenerator, KyberAgreement } = require("kyberkotlin").asia.hombre.kyber;

let aliceKeypair = KyberKeyGenerator.Companion.generate(KyberParameter.ML_KEM_512);
let bobKeypair = KyberKeyGenerator.Companion.generate(KyberParameter.ML_KEM_512);

let aliceAgreement = new KyberAgreement(aliceKeypair);
let bobAgreement = new KyberAgreement(bobKeypair);

let results = bobAgreement.encapsulate(aliceKeypair.encapsulationKey);

let ciphertext = results.cipherText;
let bobSecretKey = results.secretKey;

let aliceSecretKey = aliceAgreement.decapsulate(ciphertext);

console.assert(contentEquals(aliceSecretKey, bobSecretKey), "Secret Keys does not match!");

//Simple check
function contentEquals(a, b) {
    for(let i = 0; i < a.length; i++)
        if(a[i] !== b[i])
            return false;
    return true;
}

```

### With Native C#

> [!CAUTION]
> Native is in BETA. No one is confident it will work reliably.

```csharp
using System.Runtime.InteropServices;

//Use absolute path if relative does not work.
const string dllName = "KyberKotlin.dll";

//Declare methods from the DLL.
[DllImport(dllName, EntryPoint = "generateKeyPair")]
static extern IntPtr generateKeyPair(int parameterId);

[DllImport(dllName, EntryPoint = "getEncapsulationKeySize")]
static extern int getEncapsulationKeySize(int parameterId);

[DllImport(dllName, EntryPoint = "getDecapsulationKeySize")]
static extern int getDecapsulationKeySize(int parameterId);

[DllImport(dllName, EntryPoint = "getCipherTextSize")]
static extern int getCipherTextSize(int parameterId);

[DllImport(dllName, EntryPoint = "getSecretKeySize")]
static extern int getSecretKeySize();

[DllImport(dllName, EntryPoint = "encapsulate")]
static extern IntPtr encapsulate(byte[] encapsulationKey, int parameterId);

[DllImport(dllName, EntryPoint = "decapsulate")]
static extern IntPtr decapsulate(byte[] decapsulationKey, byte[] cipherText, int parameterId);

//Get sizes
int encapsulationKeySize = getEncapsulationKeySize(0); //0 = 512, 1 = 768, 2 = 1024
int decapsulationKeySize = getDecapsulationKeySize(0);
int cipherTextSize = getCipherTextSize(0);

//Generate Key Pair
IntPtr keysPtr = generateKeyPair(0);

byte[] encapsulationKey = new byte[encapsulationKeySize];
byte[] decapsulationKey = new byte[decapsulationKeySize];

Marshal.Copy(keysPtr, encapsulationKey, 0, encapsulationKey.Length);
Marshal.Copy(keysPtr + encapsulationKey.Length, decapsulationKey, 0, decapsulationKey.Length);

//Send encapsulation key to Bob
//Bob encapsulates using it
IntPtr cipherPtr = encapsulate(encapsulationKey, 0);

//Bob receives the Secret Key
byte[] secretKey = new byte[getSecretKeySize()];
byte[] cipherText = new byte[cipherTextSize];

Marshal.Copy(cipherPtr, secretKey, 0, secretKey.Length);
Marshal.Copy(cipherPtr + secretKey.Length, cipherText, 0, cipherText.Length);

//Bob sends the Cipher Text to Alice
//Alice uses it to get a copy of the Secret Key
IntPtr secretKeyPtr = decapsulate(decapsulationKey, cipherText, 0);

//Alice's Copy of the Secret Key
byte[] secretKey2 = new byte[getSecretKeySize()];

Marshal.Copy(secretKeyPtr, secretKey2, 0, secretKey2.Length);

Console.WriteLine("End!");
```

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

### Special Thanks

* IAmDerek for guiding me in NTT.
* grhkm for helping me with implementing NTT.
* versusdkp for providing me a link for intermediates for testing.
* FiloSottile's mlkem768 which gave me clues to fix bugs in my implementation.
* Steven Fisher's kyberJCE which helped me run my first tests and use one of its algorithms.
* and others from CryptoHack community!

### License

```
Copyright 2024 Ron Lauren Hombre

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

       https://www.apache.org/licenses/LICENSE-2.0
       
       and included as LICENSE.txt in this Project.

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
```

Although CRYSTALS-Kyber is Public Domain, this implementation is created through Hard Work by its Contributors.
Thus, the APACHE LICENSE v2.0 has been chosen.
