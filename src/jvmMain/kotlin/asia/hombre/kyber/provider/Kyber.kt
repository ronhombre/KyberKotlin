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

import java.math.BigInteger
import java.security.MessageDigest
import java.security.Provider
import java.security.SecureRandom
import kotlin.concurrent.Volatile

class Kyber: Provider {

    companion object {
        private const val serialVersionUID = 131833042842021223L
        val OID_KYBER = "1.3.6.1.4.1.2.267.8"
        val kyberInfo = "Kyber Provider (implements CRYSTALS Kyber)"
        @Volatile
        private var instance: Kyber? = null

        fun getRandom(): SecureRandom {
            return SecureRandomHolder.RANDOM
        }

        fun getInstance(): Kyber {
            if(instance == null)
                instance = Kyber()

            return instance!!
        }
    }

    val sha3_256: MessageDigest
    val sha3_512: MessageDigest

    constructor() : super("Kyber", serialVersionUID.toString(), kyberInfo) { //TODO: Fix
        put("KeyPairGenerator.Kyber512", "asia.hombre.kyber.provider.KyberKeyPairGenerator")
        put("Alg.Alias.KeyPairGenerator.Kyber512", "Kyber512")
        put("KeyPairGenerator.Kyber768", "asia.hombre.kyber.provider.KyberKeyPairGenerator")
        put("Alg.Alias.KeyPairGenerator.Kyber768", "Kyber768")
        put("KeyPairGenerator.Kyber1024", "asia.hombre.kyber.provider.KyberKeyPairGenerator")
        put("Alg.Alias.KeyPairGenerator.Kyber1024", "Kyber1024")
        put("KeyPairGenerator.Kyber", "asia.hombre.kyber.provider.KyberKeyPairGenerator")
        put("Alg.Alias.KeyPairGenerator.Kyber", "Kyber")

        put("AlgorithmParameterGenerator.Kyber", "asia.hombre.kyber.provider.KyberParameterGenerator")
        put("Alg.Alias.AlgorithmParameterGenerator.Kyber", "Kyber")
        put("Alg.Alias.KeyPairGenerator.OID.$OID_KYBER", "Kyber")
        put("Alg.Alias.KeyPairGenerator.$OID_KYBER", "Kyber")

        put("KeyAgreement.Kyber", "asia.hombre.kyber.provider.KyberKeyAgreement")
        put("Alg.Alias.KeyAgreement.Kyber", "Kyber")
        put("KeyAgreement.Kyber SupportedKeyClasses", "asia.hombre.kyber.provider.BaseKyberPublicKey"
                    + "|asia.hombre.kyber.provider.BaseKyberPublicKey")

        put("AlgorithmParameters.Kyber", "asia.hombre.kyber.spec.KyberParameterSpec")
        put("Alg.Alias.AlgorithmParameters.Kyber", "Kyber")

        put("KeyFactory.Kyber", "asia.hombre.kyber.provider.KyberKeyFactory")
        put("Alg.Alias.KeyFactory.Kyber", "Kyber")
        put("Alg.Alias.KeyFactory.OID.$OID_KYBER", "Kyber")
        put("Alg.Alias.KeyFactory.$OID_KYBER", "Kyber")

        sha3_256 = MessageDigest.getInstance("SHA3-256")
        sha3_512 = MessageDigest.getInstance("SHA3-512")
    }

    private object SecureRandomHolder {
        val RANDOM = SecureRandom()
    }

    enum class KeySize(val K: Int, val length: Int, val oid: String) {
        VARIANT_512(Params.K_512, 512, "1.3.6.1.4.1.22554.5.6.1"),
        VARIANT_768(Params.K_768, 768, "1.3.6.1.4.1.22554.5.6.2"),
        VARIANT_1024(Params.K_1024, 1024, "1.3.6.1.4.1.22554.5.6.3")
    }

    class Params {
        companion object {
            //Arbitrary Parameter set by CRYSTALS for Security
            const val N = 256

            //Q is a small prime number
            const val Q = 3329
            const val Q_PRIME = 62209 //Q^-1 mod 2^16 (I have no idea how this became 62209 but the math checks out.)

            //CPA-secure Public Key Encryption
            const val CPAPKE_BYTES = 32

            //Consequence of 2^8 + 2^7
            const val POLY_BYTES = 384

            //Noise for s and e in Algorithm 4 (Ref. kyber-specification-round3-20210804.pdf)
            const val SAMPLE_NOISE_HIGH = 3
            const val SAMPLE_NOISE_LOW = 2

            //Set by CRYSTALS for Security (k is selected to fix the lattice dimension as a multiple of n)
            const val K_512 = 2
            const val K_768 = 3
            const val K_1024 = 4

            const val POLY_VECTOR_BYTES_512 = K_512 * POLY_BYTES
            const val POLY_VECTOR_BYTES_768 = K_768 * POLY_BYTES
            const val POLY_VECTOR_BYTES_1024 = K_1024 * POLY_BYTES

            const val POLY_COMPRESSED_BYTES_512 = 128
            const val POLY_COMPRESSED_BYTES_768 = 128
            const val POLY_COMPRESSED_BYTES_1024 = 128 + 32

            const val POLY_VECTOR_COMPRESSED_BYTES_512 = K_512 * 320
            const val POLY_VECTOR_COMPRESSED_BYTES_768 = K_768 * 320
            const val POLY_VECTOR_COMPRESSED_BYTES_1024 = K_1024 * (320 + 32)

            const val INDCPA_PUBLIC_KEY_BYTES_512 = POLY_VECTOR_BYTES_512 + CPAPKE_BYTES
            const val INDCPA_PUBLIC_KEY_BYTES_768 = POLY_VECTOR_BYTES_768 + CPAPKE_BYTES
            const val INDCPA_PUBLIC_KEY_BYTES_1024 = POLY_VECTOR_BYTES_1024 + CPAPKE_BYTES

            const val INDCPA_PRIVATE_KEY_BYTES_512 = K_512 * POLY_BYTES
            const val INDCPA_PRIVATE_KEY_BYTES_768 = K_768 * POLY_BYTES
            const val INDCPA_PRIVATE_KEY_BYTES_1024 = K_1024 * POLY_BYTES

            const val PRIVATE_KEY_BYTES_512 = POLY_VECTOR_BYTES_512 + ((POLY_VECTOR_BYTES_512 + CPAPKE_BYTES) + 2 * CPAPKE_BYTES)
            const val PRIVATE_KEY_BYTES_768 = POLY_VECTOR_BYTES_768 + ((POLY_VECTOR_BYTES_768 + CPAPKE_BYTES) + 2 * CPAPKE_BYTES)
            const val PRIVATE_KEY_BYTES_1024 = POLY_VECTOR_BYTES_1024 + ((POLY_VECTOR_BYTES_1024 + CPAPKE_BYTES) + 2 * CPAPKE_BYTES)

            const val PUBLIC_KEY_BYTES_512 = POLY_VECTOR_BYTES_512 + CPAPKE_BYTES
            const val PUBLIC_KEY_BYTES_768 = POLY_VECTOR_BYTES_768 + CPAPKE_BYTES
            const val PUBLIC_KEY_BYTES_1024 = POLY_VECTOR_BYTES_1024 + CPAPKE_BYTES

            //Unknown source
            const val ENCODED_BYTES_EXTRA = 167

            const val ENCODED_PUBLIC_KEY_BYTES_512 = INDCPA_PUBLIC_KEY_BYTES_512 + ENCODED_BYTES_EXTRA
            const val ENCODED_PUBLIC_KEY_BYTES_768 = INDCPA_PUBLIC_KEY_BYTES_768 + ENCODED_BYTES_EXTRA
            const val ENCODED_PUBLIC_KEY_BYTES_1024 = INDCPA_PUBLIC_KEY_BYTES_1024 + ENCODED_BYTES_EXTRA

            const val CIPHER_TEXT_BYTES_512 = POLY_VECTOR_COMPRESSED_BYTES_512 + POLY_COMPRESSED_BYTES_512
            const val CIPHER_TEXT_BYTES_768 = POLY_VECTOR_COMPRESSED_BYTES_768 + POLY_COMPRESSED_BYTES_768
            const val CIPHER_TEXT_BYTES_1024 = POLY_VECTOR_COMPRESSED_BYTES_1024 + POLY_COMPRESSED_BYTES_1024

            const val ENCODED_CIPHER_TEXT_BYTES_512 = CIPHER_TEXT_BYTES_512 + ENCODED_BYTES_EXTRA
            const val ENCODED_CIPHER_TEXT_BYTES_768 = CIPHER_TEXT_BYTES_768 + ENCODED_BYTES_EXTRA
            const val ENCODED_CIPHER_TEXT_BYTES_1024 = CIPHER_TEXT_BYTES_1024 + ENCODED_BYTES_EXTRA

            const val SHARED_SECRET_BYTES = 32
            const val ENCODED_SHARED_SECRET_BYTES = 193

            val DEFAULT_P = BigInteger(
                "fca682ce8e12caba26efccf7110e526db078b05edecbcd1eb4a208f3ae1617ae01f35b91a47e6df63413c5e12ed0899bcd132acd50d99151bdc43ee737592e17",
                16
            )

            val DEFAULT_G = BigInteger(
                "678471b27a9cf44ee91a49c5147db1a9aaf244f05a434d6486931d2d14271b9e35030b71fd73da179069b32e2935630e1c2062354d0da20a6c416e50be794ca4",
                16
            )
        }
    }
}