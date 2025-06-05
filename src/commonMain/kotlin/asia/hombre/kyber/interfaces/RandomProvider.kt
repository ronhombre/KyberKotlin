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

package asia.hombre.kyber.interfaces

/**
 * A random source to use when generating an ML-KEM Key Pair or during encapsulation.
 */
interface RandomProvider {
    /**
     * Fills the byteArray with random bytes.
     *
     * The cryptographic security of this relies entirely on the function underneath. It is thus important to only use
     * a custom RandomProvider when [asia.hombre.kyber.internal.DefaultRandomProvider] does not provide sufficient
     * cryptographic security. In any case, the [asia.hombre.kyber.internal.DefaultRandomProvider] already uses the
     * strongest random source for each platform since [org.kotlincrypto.random.CryptoRand] wraps the default random
     * source for each platform.
     *
     * @param byteArray Any [ByteArray] needing random bytes.
     */
    fun fillWithRandom(byteArray: ByteArray)
}