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
package asia.hombre.kyber.provider

import asia.hombre.kyber.spec.KyberGenParameterSpec
import java.security.*
import java.security.spec.AlgorithmParameterSpec

class KyberParameterGenerator: AlgorithmParameterGeneratorSpi() {

    private var keySize = 0
    private lateinit var kyberKeySize: Kyber.KeySize
    private var random: SecureRandom? = null

    private fun setKeySize(keySize: Int) {
        this.kyberKeySize =
            when(keySize) {
                Kyber.KeySize.VARIANT_512.length -> Kyber.KeySize.VARIANT_512
                Kyber.KeySize.VARIANT_768.length -> Kyber.KeySize.VARIANT_768
                Kyber.KeySize.VARIANT_1024.length -> Kyber.KeySize.VARIANT_1024
                else ->
                    throw InvalidParameterException("Kyber key size must be 512, 768, or 1024." +
                            "The specific key size " + keySize + " is not supported")
            }
    }

    override fun engineInit(keySize: Int, random: SecureRandom?) {
        setKeySize(keySize)

        this.random = random
    }

    @Throws(InvalidAlgorithmParameterException::class)
    override fun engineInit(
        genParamSpec: AlgorithmParameterSpec,
        random: SecureRandom?
    ) {
        if (genParamSpec !is KyberGenParameterSpec) {
            throw InvalidAlgorithmParameterException("Invalid parameter type. Must be a KyberGenParameterSpec!")
        }
        val kyberParamSpec: KyberGenParameterSpec = genParamSpec

        keySize = kyberParamSpec.keySize
        kyberKeySize = kyberParamSpec.kyberKeySize

        setKeySize(kyberParamSpec.keySize)
        this.random = random
    }

    override fun engineGenerateParameters(): AlgorithmParameters {
        if (random == null) {
            random = SecureRandom.getInstanceStrong()
        }
        val kyberParamSpec = KyberGenParameterSpec()
        val algParams: AlgorithmParameters = AlgorithmParameters.getInstance("Kyber", Kyber.getInstance())
        algParams.init(kyberParamSpec)
        return algParams
    }
}