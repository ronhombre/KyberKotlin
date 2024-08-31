# KyberKotlin (NPM build)
### Bringing ML-KEM into Javascript from a compiled Kotlin Multiplatform Project.

Parent Source: [KyberKotlin](https://github.com/ronhombre/KyberKotlin)

Generated from parent KMM library using `./gradlew bundleNPM`

## Installation
`npm install kyberkotlin`

## Documentation
Visit [kyber.hombre.asia](https://kyber.hombre.asia). All **common** methods and classes are available in JS.

## Usage sample
```javascript
const { KyberParameter, KyberKeyGenerator } = require("kyberkotlin").asia.hombre.kyber;

let aliceKeypair = KyberKeyGenerator.generate(KyberParameter.ML_KEM_512);

//Send the Encapsulation Key to Bob and they encapsulate a Shared Secret Key with it.
let results = aliceKeypair.encapsulationKey.encapsulate();

let ciphertext = results.cipherText;
let bobSecretKey = results.sharedSecretKey; //This is Bob's copy of the Shared Secret Key

//Alice receives the Cipher Text from Bob and decapsulates the Shared Secret Key in it.
let aliceSecretKey = aliceKeypair.decapsulationKey.decapsulate(ciphertext);
//You can also decapsulate the other way -> ciphertext.decapsulate(aliceKeypair.decapsulationKey);

console.assert(contentEquals(aliceSecretKey, bobSecretKey), "Shared Secret Keys does not match!");

//Simple check
function contentEquals(a, b) {
    for(let i = 0; i < a.length; i++)
        if(a[i] !== b[i])
            return false;
    return true;
}
```

## License
```text
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