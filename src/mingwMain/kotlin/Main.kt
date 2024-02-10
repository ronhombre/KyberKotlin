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

import asia.hombre.kyber.*
import asia.hombre.kyber.exceptions.UnsupportedKyberVariantException
import kotlinx.cinterop.*
import org.kotlincrypto.SecureRandom
import kotlin.experimental.ExperimentalNativeApi

@OptIn(ExperimentalNativeApi::class, ExperimentalForeignApi::class)
@CName("freeMem")
fun freeMem(pointer: CPointer<*>?) {
    pointer?.let { nativeHeap.free(it) }
}

@OptIn(ExperimentalNativeApi::class, ExperimentalForeignApi::class)
@CName("generateKeyPair")
fun generateKeyPair(parameterId: Int): CPointer<ByteVar> {
    memScoped {
        val keys = KyberKeyGenerator.generate(KyberParameter.entries[parameterId])

        val bytes = ByteArray(keys.encapsulationKey.fullBytes.size + keys.decapsulationKey.fullBytes.size)

        keys.encapsulationKey.fullBytes.copyInto(bytes, 0)
        keys.decapsulationKey.fullBytes.copyInto(bytes, keys.encapsulationKey.fullBytes.size)

        println(bytes.size)

        val result = allocArray<ByteVar>(bytes.size)

        bytes.forEachIndexed { index, byte ->
            result[index] = byte
        }

        return result
    }
}

@OptIn(ExperimentalNativeApi::class, ExperimentalForeignApi::class)
@CName("encapsulate")
fun encapsulate(encapsulationKeyPtr: CPointer<ByteVar>, parameterId: Int): CPointer<ByteVar> {
    memScoped {
        val encapsulationKeyBytes = ByteArray(getEncapsulationKeySize(parameterId)) { index -> encapsulationKeyPtr[index] }
        val encapsulationKey = KyberEncapsulationKey.fromBytes(encapsulationKeyBytes)

        val encapsulationResult = KyberAgreement.encapsulate(encapsulationKey, SecureRandom().nextBytesOf(KyberConstants.N_BYTES))

        val output = allocArray<ByteVar>(encapsulationResult.secretKey.size + encapsulationResult.cipherText.fullBytes.size)
        encapsulationResult.secretKey.forEachIndexed { index, byte ->
            output[index] = byte
        }
        encapsulationResult.cipherText.fullBytes.forEachIndexed { index, byte ->
            output[index + KyberConstants.N_BYTES] = byte
        }
        return output
    }
}



@OptIn(ExperimentalNativeApi::class, ExperimentalForeignApi::class)
@CName("decapsulate")
fun decapsulate(decapsulationKeyPtr: CPointer<ByteVar>, cipherTextPtr: CPointer<ByteVar>, parameterId: Int): CPointer<ByteVar> {
    memScoped {
        val decapsulationKeyBytes = ByteArray(getDecapsulationKeySize(parameterId)) { index -> decapsulationKeyPtr[index] }
        val cipherTextBytes = ByteArray(getCipherTextSize(parameterId)) { index -> cipherTextPtr[index] }

        val decapsulationKey = KyberDecapsulationKey.fromBytes(decapsulationKeyBytes)
        val cipherText = KyberCipherText.fromBytes(cipherTextBytes)

        val secretKey = KyberAgreement.decapsulate(decapsulationKey, cipherText)

        val output = allocArray<ByteVar>(secretKey.size)
        secretKey.forEachIndexed { index, byte ->
            output[index] = byte
        }
        return output
    }
}

@OptIn(ExperimentalNativeApi::class)
@CName("testReturn")
fun testReturn(): Int {
    return 100
}

@OptIn(ExperimentalNativeApi::class)
@CName("getEncapsulationKeySize")
fun getEncapsulationKeySize(parameterId: Int): Int {
    if(parameterId > KyberParameter.entries.lastIndex) throw UnsupportedKyberVariantException("Parameter ID is not recognized.")

    val params = KyberParameter.entries[parameterId]

    return params.ENCAPSULATION_KEY_LENGTH
}

@OptIn(ExperimentalNativeApi::class)
@CName("getDecapsulationKeySize")
fun getDecapsulationKeySize(parameterId: Int): Int {
    if(parameterId > KyberParameter.entries.lastIndex) throw UnsupportedKyberVariantException("Parameter ID is not recognized.")

    val params = KyberParameter.entries[parameterId]

    return params.DECAPSULATION_KEY_LENGTH
}

@OptIn(ExperimentalNativeApi::class)
@CName("getCipherTextSize")
fun getCipherTextSize(parameterId: Int): Int {
    if(parameterId > KyberParameter.entries.lastIndex) throw UnsupportedKyberVariantException("Parameter ID is not recognized.")

    val params = KyberParameter.entries[parameterId]

    return params.CIPHERTEXT_LENGTH
}

@OptIn(ExperimentalNativeApi::class)
@CName("getSecretKeySize")
fun getSecretKeySize(): Int {
    return KyberConstants.N_BYTES
}