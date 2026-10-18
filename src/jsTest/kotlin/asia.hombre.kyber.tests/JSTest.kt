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

package asia.hombre.kyber.tests

import asia.hombre.kyber.KyberAgreement
import asia.hombre.kyber.KyberKeyGenerator
import asia.hombre.kyber.KyberParameter
import kotlin.test.Test

class JSTest {
    @Test
    fun jsPlayground() {

    }

    @Test
    fun jsEncapsDecaps() {
        val keyPairAlice = KyberKeyGenerator.generate(KyberParameter.ML_KEM_512)
        val keyPairBob = KyberKeyGenerator.generate(KyberParameter.ML_KEM_512)

        val agreementAlice = KyberAgreement(keyPairAlice.decapsulationKey)

        val cipherTextAlice = KyberAgreement.encapsulate(keyPairBob.encapsulationKey)

        val agreementBob = KyberAgreement(keyPairBob.decapsulationKey)

        val cipherTextBob = KyberAgreement.encapsulate(keyPairAlice.encapsulationKey)

        val secretKeyAlice = agreementAlice.decapsulate(cipherTextBob.cipherText)
        val secretKeyBob = agreementBob.decapsulate(cipherTextAlice.cipherText)

        println("Gen: " + cipherTextAlice.secretKey.joinToString(", "))
        println("Rec: " + secretKeyBob.joinToString(", "))

        println("Gen: " + cipherTextBob.secretKey.joinToString(", "))
        println("Rec: " + secretKeyAlice.joinToString(", "))
    }
}