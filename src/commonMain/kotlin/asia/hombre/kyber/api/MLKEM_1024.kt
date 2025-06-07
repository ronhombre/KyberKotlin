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

package asia.hombre.kyber.api

import asia.hombre.kyber.KyberKEMKeyPair
import asia.hombre.kyber.KyberKeyGenerator
import asia.hombre.kyber.KyberParameter
import asia.hombre.kyber.interfaces.MLKEM
import asia.hombre.kyber.interfaces.RandomProvider
import asia.hombre.kyber.DefaultRandomProvider

/**
 * ML-KEM-1024 (RBG Strength: 256, NIST Security Category: 5)
 *
 * @constructor Uses a [RandomProvider] when specified. All calls to [generate] will then use that as a random source.
 * @author Ron Lauren Hombre
 * @since 2.0.0
 */
class MLKEM_1024(private val randomProvider: RandomProvider = DefaultRandomProvider): MLKEM {
    override val parameter: KyberParameter = KyberParameter.ML_KEM_1024
    override fun generate(): KyberKEMKeyPair = KyberKeyGenerator.generate(parameter, randomProvider)
}