Parent Source: [KyberKotlin](https://github.com/ronhombre/KyberKotlin)

Generated from parent using `./gradlew jsBrowserProductionWebpack`

## Usage sample
```javascript
const { KyberParameter, KyberKeyGenerator, KyberAgreement } = require("./kotlin/KyberKotlin").asia.hombre.kyber;

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