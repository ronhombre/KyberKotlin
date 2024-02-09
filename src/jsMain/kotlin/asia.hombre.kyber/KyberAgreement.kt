/*
 * Copyright 2024 Ron Lauren Hombre
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 *        and included as LICENSE.txt in this Project.
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package asia.hombre.kyber

/*
 * Copyright 2024 Ron Lauren Hombre
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 *        and included as LICENSE.txt in this Project.
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

class KyberAgreement(kemKeyPair: KyberKEMKeyPair) {
    private val kyberAgreement: KyberAgreement
    val parameter: KyberParameter
        get() = kyberAgreement.parameter
    val keypair: KyberKEMKeyPair
        get() = kyberAgreement.keypair

    init {
        kyberAgreement = KyberAgreement(kemKeyPair)
    }

    fun encapsulate(kyberEncapsulationKey: KyberEncapsulationKey): KyberEncapsulationResult {
        val crypto: dynamic = js("require('crypto')")

        val plainText = crypto.randomBytes(KyberConstants.N_BYTES) as ByteArray

        return kyberAgreement.encapsulate(kyberEncapsulationKey, plainText)
    }

    fun decapsulate(cipherText: KyberCipherText): ByteArray {
        return kyberAgreement.decapsulate(cipherText)
    }
}