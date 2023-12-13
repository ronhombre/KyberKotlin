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
package asia.hombre.kyber.util

import asia.hombre.kyber.provider.Kyber
import asia.hombre.kyber.provider.KyberPublicKey
import asia.hombre.kyber.spec.KyberPublicKeySpec
import java.math.BigInteger
import java.security.InvalidKeyException
import java.security.Key
import java.security.NoSuchAlgorithmException
import java.security.SecureRandom
import java.security.spec.KeySpec

internal class KyberKeyUtil {
    companion object {
        @Throws(InvalidKeyException::class)
        fun validate(key: Key?) {
            if (key == null) {
                throw NullPointerException(
                    "The key to be validated cannot be null"
                )
            }
            if (key is KyberPublicKey) {
                validateKyberPublicKey(key)
            }
        }

        @Throws(InvalidKeyException::class)
        fun validate(keySpec: KeySpec?) {
            if (keySpec == null) {
                throw NullPointerException(
                    "The key spec to be validated cannot be null"
                )
            }
            if (keySpec is KyberPublicKeySpec) {
                validateKyberPublicKey(keySpec)
            }
        }

        @Throws(InvalidKeyException::class)
        private fun validateKyberPublicKey(publicKey: KyberPublicKey) {
            val length: Int = publicKey.y.size
            if (length != 800 && length != 1184 && length != 1568) {
                throw InvalidKeyException("Unsupported Key Length $length")
            }
        }

        @Throws(InvalidKeyException::class)
        private fun validateKyberPublicKey(publicKeySpec: KyberPublicKeySpec) {
            val length: Int = publicKeySpec.y.size
            if (length != 800 && length != 1184 && length != 1568) {
                throw InvalidKeyException("Unsupported Key Length $length")
            }
        }

        fun constantTimeCompare(x: ByteArray, y: ByteArray): Int {
            if (x.size != y.size) {
                return 1
            }
            var v: Byte = 0
            for (i in x.indices) {
                v = ((v.toInt() and 0xFF) or ((x[i].toInt() and 0xFF) xor (y[i].toInt() and 0xFF))).toByte()
            }
            return v.compareTo(0.toByte())
        }

        @Throws(InvalidKeyException::class)
        fun getKyberKeySizeFromPrivateKey(length: Int): Kyber.KeySize {
            return when(length) {
                Kyber.Params.PRIVATE_KEY_BYTES_512 -> Kyber.KeySize.VARIANT_512
                Kyber.Params.PRIVATE_KEY_BYTES_768 -> Kyber.KeySize.VARIANT_768
                Kyber.Params.PRIVATE_KEY_BYTES_1024 -> Kyber.KeySize.VARIANT_1024
                else ->
                    throw InvalidKeyException("Unsupported Private Key Length: $length")
            }
        }

        @Throws(InvalidKeyException::class)
        fun getKyberKeySizeFromPublicKey(length: Int): Kyber.KeySize {
            return when(length) {
                Kyber.Params.PUBLIC_KEY_BYTES_512 -> Kyber.KeySize.VARIANT_512
                Kyber.Params.PUBLIC_KEY_BYTES_768 -> Kyber.KeySize.VARIANT_768
                Kyber.Params.PUBLIC_KEY_BYTES_1024 -> Kyber.KeySize.VARIANT_1024
                else ->
                    throw InvalidKeyException("Unsupported Public Key Length: $length")
            }
        }

        /**
         * Generate a random p
         *
         * @return
         * @throws NoSuchAlgorithmException
         */
        @Throws(NoSuchAlgorithmException::class)
        fun randomP(): BigInteger {
            val rand = SecureRandom.getInstanceStrong()
            val p = ByteArray(128)
            rand.nextBytes(p)
            return BigInteger(p)
        }

        /**
         * Generate a random G
         *
         * @return
         * @throws NoSuchAlgorithmException
         */
        @Throws(NoSuchAlgorithmException::class)
        fun randomG(): BigInteger {
            val rand = SecureRandom.getInstanceStrong()
            val g = ByteArray(128)
            rand.nextBytes(g)
            return BigInteger(g)
        }
    }
}