/*
 * Copyright 2025 Ron Lauren Hombre
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

import kotlin.js.ExperimentalJsExport
import kotlin.js.JsExport

/**
 * A class for K-PKE Encryption and Decryption Key Pairs.
 *
 * This class contains the Encryption and Decryption Key.
 *
 * @constructor Stores the Encryption Key and the Decryption Key as a pair.
 * @author Ron Lauren Hombre
 */
@OptIn(ExperimentalJsExport::class)
@JsExport
class KyberPKEKeyPair internal constructor(
    /**
     * The [KyberEncryptionKey].
     */
    val encryptionKey: KyberEncryptionKey,
    /**
     * The [KyberDecryptionKey].
     */
    val decryptionKey: KyberDecryptionKey
) {

    /**
     * Create an independent copy from an untrusted source.
     *
     * @return [KyberPKEKeyPair]
     */
    fun copy(): KyberPKEKeyPair {
        return KyberPKEKeyPair(encryptionKey.copy(), decryptionKey.copy())
    }

    /**
     * Deep equality check.
     *
     * @return [Boolean]
     */
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as KyberPKEKeyPair

        if (encryptionKey != other.encryptionKey) return false
        if (decryptionKey != other.decryptionKey) return false

        return true
    }

    override fun hashCode(): Int {
        var result = encryptionKey.hashCode()
        result = 31 * result + decryptionKey.hashCode()
        return result
    }
}