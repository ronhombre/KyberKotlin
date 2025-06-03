# KyberKotlin (1.2.0)
## _Implements ML-KEM (CRYSTALS-Kyber)_
_**Digital security for all, everywhere, no matter who they are, or what they believe in.**_

[![CodeQL master](https://github.com/ronhombre/KyberKotlin/actions/workflows/codeql.yml/badge.svg)](https://github.com/ronhombre/KyberKotlin/actions/workflows/codeql.yml)
[![Maven Central](https://img.shields.io/maven-central/v/asia.hombre/kyber.svg)](https://search.maven.org/#search%7Cga%7C1%7Cg%3A%22asia.hombre%22)
[![GitHub license](https://img.shields.io/badge/license-Apache%20License%202.0-blue.svg?style=flat)](https://www.apache.org/licenses/LICENSE-2.0)
![Gradle](https://img.shields.io/badge/Gradle-02303A.svg?style=for-the-badge&logo=Gradle&logoColor=white)
![Kotlin](https://img.shields.io/badge/kotlin-%237F52FF.svg?style=for-the-badge&logo=kotlin&logoColor=white)
![Java](https://img.shields.io/badge/java-%23ED8B00.svg?style=for-the-badge&logo=openjdk&logoColor=white)
![JS](https://img.shields.io/badge/JavaScript-F7DF1E?style=for-the-badge&logo=javascript&logoColor=black)
![Linux Arm64 & X64](https://img.shields.io/badge/Linux-FCC624?style=for-the-badge&logo=linux&logoColor=black)
![Windows X64](https://img.shields.io/badge/Windows-0078D6?style=for-the-badge&logo=windows&logoColor=white)
![iOS Arm64 & X64](https://img.shields.io/badge/iOS-000000?style=for-the-badge&logo=ios&logoColor=white)
![Android Arm32, Arm64, & X64](https://img.shields.io/badge/Android-3DDC84?style=for-the-badge&logo=android&logoColor=white)

> **ML-KEM** is a key-encapsulation mechanism based on _CRYSTALS-KYBER_. The security of ML-KEM is based on the presumed
> hardness of the so-called Module Learning with Errors (MLWE) problem, which is a generalization of the Learning With
> Errors (LWE) problem introduced by Regev in 2005. The hardness of the MLWE problem is itself based on the presumed
> hardness of certain computational problems in module lattices. This motivates the name of the scheme ML-KEM.

*This is quoted from 
[Section 3.2](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.203.pdf) of the NIST FIPS 203 document.*

> [!WARNING]
> If you are using any versions below 1.2.0, you must update to 1.2.0 and above to fix a critical vulnerability in this
> implementation. In summary, the previous versions were NOT ML-KEM but Kyber. There is a big difference between the
> two. In addition, the algorithm was sometimes producing rare bit flips that doesn't affect the encaps, decaps process,
> but it is still a different result than the implementation of others so it would cause confusion once mixed with other
> libraries seen in #14.

## Introduction

This is a 100% Kotlin Multiplatform implementation of ML-KEM Final.
It depends on [KeccakKotlin](https://github.com/ronhombre/KeccakKotlin) and [secure-random](https://github.com/KotlinCrypto/secure-random) Kotlin libraries in order to implement SHA3, SHAKE, and
Secure Random within the library.

> [!NOTE]
> With the release of the final version of NIST FIPS 203 for ML-KEM, I'm proud to present that my KyberKotlin library is
> ready for production use. In the past months, there have been no reports about any problems.

## Capabilities
* Key Generation (512, 768, 1024)
* Encapsulation (512, 768, 1024)
* Decapsulation (512, 768, 1024)
* Convert to or from bytes.

## Tested Platforms
* JVM (Java, Kotlin)
* Javascript (NPM)

## Supported Targets

| Target                    | Arm32              | Arm64              | X64                |
|---------------------------|--------------------|--------------------|--------------------|
| JVM (Kotlin & Java)       | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| JS (Node, Bun, & Browser) | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| Linux                     | :x: *              | :x: **             | :white_check_mark: |
| Windows (Mingw)           | :x: *              | :x: *              | :white_check_mark: |
| Android                   | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| iOS                       | :x: *              | :x: **             | :x: **             |
| iOS Simulator             | :x: *              | :x: **             | :x: *              |

*Note: Some platforms are unavailable/deprecated as targets in Kotlin Multiplatform. Please send your complaints to Jetbrains.

**These targets are currently available, but I have no ability to compile them **yet**. Once I have more free time, I will setup a publishing server to compile to all targets.

## Documentation
* [kyber.hombre.asia](https://kyber.hombre.asia)

## Installation
### JVM (Kotlin, Java, Android)

**Requirements: JAVA 8+**

NOTE: if _implementation_ does not work, replace with _compile_.

### Gradle through Maven

`build.gradle`

```groovy
dependencies {
    implementation 'asia.hombre:kyber:1.2.0'
}
```

### Gradle Kotlin through Maven

`build.gradle.kts`

```kotlin
dependencies {
    implementation("asia.hombre:kyber:1.2.0")
}
```

### Maven

`pom.xml`

```xml
<dependency>
    <groupId>asia.hombre</groupId>
    <artifactId>kyber</artifactId>
    <version>1.2.0</version>
</dependency>
```

Checkout the [Wiki](https://github.com/ronhombre/KyberKotlin/wiki/Installation) for more installation instructions and examples.

## API Usage

Checkout the Wiki or the Documentation for more information.

### References

* [NIST FIPS 203](https://csrc.nist.gov/pubs/fips/203/final)
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
Copyright 2025 Ron Lauren Hombre

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

Although ML-KEM is declared Public Domain, this implementation is created through the efforts of its contributors. As
such, some form of recognition for their work are required for all users of this library.
