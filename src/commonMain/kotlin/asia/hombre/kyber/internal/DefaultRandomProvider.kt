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

package asia.hombre.kyber.internal

import asia.hombre.kyber.interfaces.RandomProvider
import org.kotlincrypto.random.CryptoRand

/**
 * The default [RandomProvider] for use when the [RandomProvider] is not specified.
 *
 * Changing this is not recommended unless you have sufficient motivation to do so. Please read [CryptoRand]'s
 * source code before deciding on anything.
 *
 * @author Ron Lauren Hombre
 */
object DefaultRandomProvider: RandomProvider {
    /**
     * Uses [CryptoRand.Default] as a random source. This is an external library which wraps each platform's default
     * random source to a common API.
     */
    override fun fillWithRandom(byteArray: ByteArray) {
        CryptoRand.Default.nextBytes(byteArray)
    }
}