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
package asia.hombre.kyber.spec

import java.math.BigInteger
import java.security.spec.AlgorithmParameterSpec

class KyberParameterSpec(
    val p: BigInteger,
    val g: BigInteger,
    val l: Int
) : AlgorithmParameterSpec {
    override fun equals(other: Any?): Boolean {
        if(other is KyberParameterSpec)
            return this.p == other.p && this.g == other.g && this.l == other.l

        return false
    }

    override fun hashCode(): Int {
        var result = p.hashCode()
        result = 31 * result + g.hashCode()
        result = 31 * result + l
        return result
    }
}