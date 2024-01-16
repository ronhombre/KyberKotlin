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

import java.security.SecureRandom

class KyberKeyGenerator {
    companion object {
        @JvmStatic
        fun generate(parameter: KyberParameter): KyberKEMKeyPair {
            val randomSeed = ByteArray(KyberConstants.N_BYTES)
            val pkeSeed = ByteArray(KyberConstants.N_BYTES)

            //New SecureRandom instance for each call to avoid patterns for multiple key generations.
            val random: SecureRandom = SecureRandom.getInstanceStrong()

            random.nextBytes(randomSeed)
            random.nextBytes(pkeSeed)

            return KyberKeyPairGenerator.generate(
                parameter,
                randomSeed,
                pkeSeed
            )
        }
    }
}