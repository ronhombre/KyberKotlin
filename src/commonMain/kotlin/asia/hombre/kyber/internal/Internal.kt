/*
 * Copyright 2026 Ron Lauren Hombre
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

import asia.hombre.keccak.internal.AbstractKeccakFunction
import asia.hombre.kyber.KyberConstants
import asia.hombre.kyber.KyberParameter
import kotlin.jvm.JvmSynthetic

@JvmSynthetic
internal fun ByteArray.asBuffer(): ByteBuffer {
    return ByteBuffer(this)
}

@JvmSynthetic
internal fun AbstractKeccakFunction.update(buffer: ByteBuffer) {
    this.update(buffer.array, buffer.offset, buffer.size)
}

@JvmSynthetic
internal fun ByteBuffer.sliceOfDecryptionKey(parameter: KyberParameter) = slice(0, parameter.DECRYPTION_KEY_LENGTH)
@JvmSynthetic
internal fun ByteBuffer.sliceOfEncryptionKey(parameter: KyberParameter) = slice(parameter.DECRYPTION_KEY_LENGTH, parameter.DECRYPTION_KEY_LENGTH + parameter.ENCRYPTION_KEY_LENGTH)
@JvmSynthetic
internal fun ByteBuffer.sliceOfHash() = slice(this.size - 2 * KyberConstants.N_BYTES, this.size - KyberConstants.N_BYTES)
@JvmSynthetic
internal fun ByteBuffer.sliceOfRandomSeed() = slice(this.size - KyberConstants.N_BYTES, this.size)

@JvmSynthetic
internal fun ByteBuffer.sliceOfKeyBytes(parameter: KyberParameter) = slice(0, parameter.DECRYPTION_KEY_LENGTH)
@JvmSynthetic
internal fun ByteBuffer.sliceOfNTTSeed(parameter: KyberParameter) = slice(parameter.DECRYPTION_KEY_LENGTH)

@JvmSynthetic
internal fun ByteBuffer.sliceOfEncodedCoefficients(parameter: KyberParameter) = slice(0, KyberConstants.N_BYTES * parameter.DU * parameter.K)
@JvmSynthetic
internal fun ByteBuffer.sliceOfEncodedTerms(parameter: KyberParameter) = slice(KyberConstants.N_BYTES * parameter.DU * parameter.K)