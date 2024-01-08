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

import asia.hombre.kyber.security.KyberINDCPA
import asia.hombre.kyber.spec.KyberParameterSpec
import java.security.*
import java.security.spec.AlgorithmParameterSpec

class KyberKeyPairGenerator: KeyPairGeneratorSpi() {
    private lateinit var kyberKeySize: Kyber.KeySize
    private lateinit var random: SecureRandom

    override fun initialize(keySize: Int, random: SecureRandom) {
        setKeySize(keySize)

        this.random = random
    }

    @Throws(InvalidAlgorithmParameterException::class)
    override fun initialize(algParams: AlgorithmParameterSpec, random: SecureRandom) {
        if (algParams !is KyberParameterSpec)
            throw InvalidAlgorithmParameterException("Invalid parameter type. Must be a KyberParameterSpec!")

        setKeySize(algParams.l)

        this.random = random
    }

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

    override fun generateKeyPair(): KeyPair {
        return generateKyberKeyPair().keyPair
    }

    private fun generateKyberKeyPair(): KyberKeyPair {
        val privateKeyLength = when(kyberKeySize) {
            Kyber.KeySize.VARIANT_512 -> Kyber.Params.PRIVATE_KEY_BYTES_512
            Kyber.KeySize.VARIANT_768 -> Kyber.Params.PRIVATE_KEY_BYTES_768
            Kyber.KeySize.VARIANT_1024 -> Kyber.Params.PRIVATE_KEY_BYTES_1024
        }

        try {
            val rawKeyPair: Pair<ByteArray, ByteArray> = KyberINDCPA.generateKyberKeys(kyberKeySize.K)

            val privateKeyFixedLength = ByteArray(privateKeyLength)

            val md: MessageDigest = MessageDigest.getInstance("SHA3-256")
            val encodedHash = md.digest(rawKeyPair.first)
            val pkh = ByteArray(encodedHash.size)

            System.arraycopy(encodedHash, 0, pkh, 0, encodedHash.size)

            val rnd = ByteArray(Kyber.Params.CPAPKE_BYTES)

            this.random.nextBytes(rnd)

            var offsetEnd = rawKeyPair.second.size

            System.arraycopy(rawKeyPair.second, 0, privateKeyFixedLength, 0, offsetEnd)
            System.arraycopy(rawKeyPair.first, 0, privateKeyFixedLength, offsetEnd, rawKeyPair.first.size)

            offsetEnd += rawKeyPair.first.size

            System.arraycopy(pkh, 0, privateKeyFixedLength, offsetEnd, pkh.size)

            offsetEnd += pkh.size

            System.arraycopy(rnd, 0, privateKeyFixedLength, offsetEnd, rnd.size)

            return KyberKeyPair(
                KyberPublicKey(rawKeyPair.first, Kyber.Params.DEFAULT_P, Kyber.Params.DEFAULT_G),
                KyberPrivateKey(privateKeyFixedLength, Kyber.Params.DEFAULT_P, Kyber.Params.DEFAULT_G)
            )
        } catch (e: Exception) {
            throw e
        }
    }
}