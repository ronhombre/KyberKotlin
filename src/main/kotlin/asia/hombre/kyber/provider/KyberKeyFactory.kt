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

import asia.hombre.kyber.`interface`.BaseKyberPrivateKey
import asia.hombre.kyber.`interface`.BaseKyberPublicKey
import asia.hombre.kyber.spec.KyberParameterSpec
import asia.hombre.kyber.spec.KyberPrivateKeySpec
import asia.hombre.kyber.spec.KyberPublicKeySpec
import java.security.*
import java.security.spec.InvalidKeySpecException
import java.security.spec.KeySpec
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec

class KyberKeyFactory: KeyFactorySpi() {

    @Throws(InvalidKeySpecException::class)
    override fun engineGeneratePublic(keySpec: KeySpec): PublicKey {
        return try {
            if (keySpec is KyberPublicKeySpec) {
                KyberPublicKey(
                    keySpec.y,
                    keySpec.p,
                    keySpec.g
                )
            } else if (keySpec is X509EncodedKeySpec) {
                KyberPublicKey(keySpec.encoded)
            } else {
                throw InvalidKeySpecException("Inappropriate key specification")
            }
        } catch (e: InvalidKeyException) {
            throw InvalidKeySpecException("Inappropriate key specification", e)
        }
    }

    @Throws(InvalidKeySpecException::class)
    override fun engineGeneratePrivate(keySpec: KeySpec): PrivateKey {
        return try {
            if (keySpec is KyberPrivateKeySpec) {
                KyberPrivateKey(
                    keySpec.x,
                    keySpec.p,
                    keySpec.g
                )
            } else if (keySpec is PKCS8EncodedKeySpec) {
                KyberPrivateKey(keySpec.encoded)
            } else {
                throw InvalidKeySpecException("Inappropriate key specification")
            }
        } catch (e: InvalidKeyException) {
            throw InvalidKeySpecException("Inappropriate key specification", e)
        }
    }

    @Throws(InvalidKeySpecException::class)
    override fun <T : KeySpec?> engineGetKeySpec(key: Key, keySpec: Class<T>): T {
        val params: KyberParameterSpec
        return if (key is KyberPublicKey) {
            if (KyberPublicKeySpec::class.java.isAssignableFrom(keySpec)) {
                params = key.params
                keySpec.cast(
                    KyberPublicKeySpec(
                        key.y,
                        params.p,
                        params.g, key.kyberKeySize
                    )
                )
            } else if (X509EncodedKeySpec::class.java.isAssignableFrom(keySpec)) {
                keySpec.cast(X509EncodedKeySpec(key.encoded))
            } else {
                throw InvalidKeySpecException("Inappropriate key specification")
            }
        } else if (key is KyberPrivateKey) {
            if (KyberPrivateKeySpec::class.java.isAssignableFrom(keySpec)) {
                params = key.params
                keySpec.cast(
                    KyberPrivateKeySpec(
                        key.x,
                        params.p,
                        params.g, key.kyberKeySize
                    )
                )
            } else if (PKCS8EncodedKeySpec::class.java.isAssignableFrom(keySpec)) {
                keySpec.cast(PKCS8EncodedKeySpec(key.encoded))
            } else {
                throw InvalidKeySpecException("Inappropriate key specification")
            }
        } else {
            throw InvalidKeySpecException("Inappropriate key type")
        }
    }

    @Throws(InvalidKeyException::class)
    override fun engineTranslateKey(key: Key): Key {
        return try {
            if (key is BaseKyberPublicKey) {
                // Check if key originates from this factory
                if (key is KyberPublicKey) {
                    return key
                }
                // Convert key to spec
                val kyberPubKeySpec: KyberPublicKeySpec = engineGetKeySpec(key, KyberPublicKeySpec::class.java)
                // Create key from spec, and return it
                engineGeneratePublic(kyberPubKeySpec)
            } else if (key is BaseKyberPrivateKey) {
                // Check if key originates from this factory
                if (key is KyberPrivateKey) {
                    return key
                }
                // Convert key to spec
                val kyberPrivKeySpec: KyberPrivateKeySpec = engineGetKeySpec(key, KyberPrivateKeySpec::class.java)
                // Create key from spec, and return it
                engineGeneratePrivate(kyberPrivKeySpec)
            } else {
                throw InvalidKeyException("Wrong algorithm type")
            }
        } catch (e: InvalidKeySpecException) {
            throw InvalidKeyException("Cannot translate key", e)
        }
    }
}