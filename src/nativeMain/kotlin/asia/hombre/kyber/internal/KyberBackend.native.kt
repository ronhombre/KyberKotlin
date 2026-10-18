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
@file:OptIn(ExperimentalForeignApi::class, UnsafeNumber::class)

package asia.hombre.kyber.internal

import asia.hombre.kyber.*
import asia.hombre.kyber.exceptions.*
import asia.hombre.kyber.rust.*
import kotlinx.cinterop.*

internal actual object KyberBackend {
    actual fun generate(parameter: KyberParameter, randomSeed: ByteArray, pkeSeed: ByteArray): KyberKEMKeyPair {
        val output = ByteArray(parameter.DECAPSULATION_KEY_LENGTH)
        val seedBuffer = ByteArray(KyberConstants.N_BYTES * 2)
        randomSeed.copyInto(seedBuffer, 0, 0, KyberConstants.N_BYTES)
        pkeSeed.copyInto(seedBuffer, KyberConstants.N_BYTES, 0, KyberConstants.N_BYTES)
        try {
            val status = seedBuffer.withPointer { seeds ->
                output.withPointer { out ->
                    kyberrust_generate(
                        parameter.K.toUInt(),
                        seeds,
                        seedBuffer.size.convert(),
                        out,
                        output.size.convert()
                    )
                }
            }
            checkRustStatus(status)
            val dk = KyberDecapsulationKey(parameter, ByteBuffer(output))
            return KyberKEMKeyPair(KyberEncapsulationKey(dk.encryptionKey), dk)
        } finally {
            pkeSeed.fill(0)
        }
    }

    actual fun generate(parameter: KyberParameter, pkeSeed: ByteArray): KyberPKEKeyPair {
        val output = ByteArray(parameter.DECRYPTION_KEY_LENGTH + parameter.ENCRYPTION_KEY_LENGTH)
        try {
            val status = pkeSeed.withPointer { d ->
                output.withPointer { out ->
                    kyberrust_generate_pke(
                        parameter.K.toUInt(),
                        d,
                        pkeSeed.size.convert(),
                        out,
                        output.size.convert()
                    )
                }
            }
            checkRustStatus(status)
            val bytes = ByteBuffer(output)
            return KyberPKEKeyPair(
                KyberEncryptionKey(parameter, bytes.sliceOfEncryptionKey(parameter)),
                KyberDecryptionKey(parameter, bytes.sliceOfDecryptionKey(parameter)),
            )
        } finally {
            pkeSeed.fill(0)
        }
    }

    actual fun encapsulate(key: KyberEncapsulationKey, plainText: ByteArray): KyberEncapsulationResult {
        val parameter = key.key.parameter
        val bytes = key.key.bytes
        val output = ByteArray(KyberConstants.SECRET_KEY_LENGTH + parameter.CIPHERTEXT_LENGTH)
        plainText.copyInto(output, 0, 0, plainText.size)
        try {
            val status = bytes.withPointer { ek ->
                output.withPointer { out ->
                    kyberrust_encapsulate(
                        parameter.K.toUInt(),
                        ek,
                        bytes.size.convert(),
                        out,
                        output.size.convert()
                    )
                }
            }
            checkRustStatus(status)
            val result = ByteBuffer(output)
            return KyberEncapsulationResult(
                result.slice(0, KyberConstants.SECRET_KEY_LENGTH),
                KyberCipherText(parameter, result.slice(KyberConstants.SECRET_KEY_LENGTH)),
            )
        } finally {
            plainText.fill(0)
        }
    }

    actual fun decapsulate(key: KyberDecapsulationKey, cipherText: KyberCipherText): ByteArray {
        if (key.parameter != cipherText.parameter) throw MismatchingKyberVariantException()
        val output = ByteArray(KyberConstants.SECRET_KEY_LENGTH)
        val status = key.bytes.withPointer { dk ->
            cipherText.bytes.withPointer { ct ->
                output.withPointer { out ->
                    kyberrust_decapsulate(
                        key.parameter.K.toUInt(),
                        dk,
                        key.bytes.size.convert(),
                        ct,
                        cipherText.bytes.size.convert(),
                        out,
                        output.size.convert()
                    )
                }
            }
        }
        checkRustStatus(status)
        return output
    }

    actual fun encrypt(key: KyberEncryptionKey, plainText: ByteArray, randomness: ByteArray): KyberCipherText {
        val output = ByteArray(key.parameter.CIPHERTEXT_LENGTH)
        val byteBuffer = ByteArray(KyberConstants.N_BYTES * 2)
        plainText.copyInto(byteBuffer, 0, 0, KyberConstants.N_BYTES)
        randomness.copyInto(byteBuffer, KyberConstants.N_BYTES, 0, KyberConstants.N_BYTES)
        try {
            val status = key.bytes.withPointer { ek ->
                byteBuffer.withPointer { buffer ->
                    output.withPointer { out ->
                        kyberrust_encrypt(
                            key.parameter.K.toUInt(),
                            ek,
                            key.bytes.size.convert(),
                            buffer,
                            byteBuffer.size.convert(),
                            out,
                            output.size.convert()
                        )
                    }
                }
            }
            checkRustStatus(status)
            return KyberCipherText(key.parameter, ByteBuffer(output))
        } finally {
            plainText.fill(0)
            randomness.fill(0)
        }
    }

    actual fun decrypt(key: KyberDecryptionKey, cipherText: KyberCipherText): ByteArray {
        if (key.parameter != cipherText.parameter) throw MismatchingKyberVariantException()
        val output = ByteArray(KyberConstants.N_BYTES)
        val status = key.keyBytes.withPointer { dk ->
            cipherText.bytes.withPointer { ct ->
                output.withPointer { out ->
                    kyberrust_decrypt(
                        key.parameter.K.toUInt(),
                        dk,
                        key.keyBytes.size.convert(),
                        ct,
                        cipherText.bytes.size.convert(),
                        out,
                        output.size.convert()
                    )
                }
            }
        }
        checkRustStatus(status)
        return output
    }
}

private inline fun <T> ByteArray.withPointer(block: (CPointer<UByteVar>) -> T): T =
    usePinned { block(it.addressOf(0).reinterpret()) }

private inline fun <T> ByteBuffer.withPointer(block: (CPointer<UByteVar>) -> T): T =
    array.usePinned { block(it.addressOf(offset).reinterpret()) }

internal fun checkRustStatus(status: Int) {
    when (status) {
        KYBERRUST_SUCCESS -> Unit
        KYBERRUST_INVALID_KEY -> throw InvalidKyberKeyException("Rust rejected the key or ciphertext encoding.")
        KYBERRUST_RANDOM_FAILURE -> throw RandomBitGenerationException()
        KYBERRUST_UNSUPPORTED_VARIANT -> throw UnsupportedKyberVariantException("Rust does not support this parameter set.")
        KYBERRUST_BUFFER_TOO_SMALL -> throw BufferTooSmallException()
        KYBERRUST_MISMATCHING_VARIANT -> throw MismatchingKyberVariantException()
        KYBERRUST_INVALID_BUFFER -> throw InvalidBufferException()
        else -> error("Unknown KyberRust status: $status")
    }
}
