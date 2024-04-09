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

import kotlin.js.ExperimentalJsExport
import kotlin.js.JsExport

/**
 * A class for ML-KEM Encapsulation and Decapsulation Key Pairs.
 *
 * This class contains the Encapsulation and Decapsulation Key.
 *
 * @constructor Stores the Encapsulation Key and the Decapsulation Key as a pair.
 * @author Ron Lauren Hombre
 */
@OptIn(ExperimentalJsExport::class)
@JsExport
class KyberKEMKeyPair internal constructor(
    /**
     * The [KyberEncapsulationKey].
     */
    val encapsulationKey: KyberEncapsulationKey,
    /**
     * The [KyberDecapsulationKey].
     */
    val decapsulationKey: KyberDecapsulationKey
) {

    /**
     * Create an independent copy from an untrusted source.
     *
     * @return [KyberKEMKeyPair]
     */
    fun copy(): KyberKEMKeyPair {
        return KyberKEMKeyPair(encapsulationKey.copy(), decapsulationKey.copy())
    }

    /**
     * Deep equality check.
     *
     * @return [Boolean]
     */
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as KyberKEMKeyPair

        if (encapsulationKey != other.encapsulationKey) return false
        if (decapsulationKey != other.decapsulationKey) return false

        return true
    }

    override fun hashCode(): Int {
        var result = encapsulationKey.hashCode()
        result = 31 * result + decapsulationKey.hashCode()
        return result
    }
}