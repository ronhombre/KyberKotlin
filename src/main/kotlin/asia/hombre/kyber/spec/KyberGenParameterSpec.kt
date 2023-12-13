//Copyright 2023 Ron Lauren Hombre
//
//Licensed under the Apache License, Version 2.0 (the "License");
//you may not use this file except in compliance with the License.
//You may obtain a copy of the License at
//
//       http://www.apache.org/licenses/LICENSE-2.0
//
//       and included as LICENSE.txt in this Project.
//
//Unless required by applicable law or agreed to in writing, software
//distributed under the License is distributed on an "AS IS" BASIS,
//WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//See the License for the specific language governing permissions and
//limitations under the License.
package asia.hombre.kyber.spec

import asia.hombre.kyber.provider.Kyber
import java.security.InvalidParameterException
import java.security.spec.AlgorithmParameterSpec

class KyberGenParameterSpec : AlgorithmParameterSpec {
    val keySize: Int
    val kyberKeySize: Kyber.KeySize

    constructor() {
        keySize = 768
        kyberKeySize = Kyber.KeySize.VARIANT_768
    }

    constructor(keySize: Int) {
        this.keySize = keySize
        kyberKeySize = when(keySize) {
                Kyber.KeySize.VARIANT_512.length -> Kyber.KeySize.VARIANT_512
                Kyber.KeySize.VARIANT_768.length -> Kyber.KeySize.VARIANT_768
                Kyber.KeySize.VARIANT_1024.length -> Kyber.KeySize.VARIANT_1024
                else ->
                    throw InvalidParameterException("Kyber key size must be 512, 768, or 1024." +
                            "The specific key size " + keySize + " is not yet supported")
            }
    }
}