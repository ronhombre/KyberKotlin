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

import kotlin.jvm.JvmField

enum class KyberParameter(val K: Int, val ETA1: Int, val ETA2: Int, val DU: Int, val DV: Int) {
    ML_KEM_512(2, 3, 2, 10, 4),
    ML_KEM_768(3, 2, 2, 10, 4),
    ML_KEM_1024(4, 2, 2, 11, 5);

    @JvmField
    val CIPHERTEXT_LENGTH: Int = KyberConstants.N_BYTES * ((DU * K) + DV)

    @JvmField
    val ENCAPSULATION_KEY_LENGTH: Int = (3 * KyberConstants.N * K shr 1) + KyberConstants.SECRET_KEY_LENGTH

    @JvmField
    val DECAPSULATION_KEY_LENGTH: Int = (2 * ENCAPSULATION_KEY_LENGTH) + KyberConstants.N_BYTES
}