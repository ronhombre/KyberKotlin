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

import asia.hombre.kyber.internal.KyberMath
import asia.hombre.kyber.internal.SecureRandom
import org.kotlincrypto.hash.sha3.SHA3_256
import org.kotlincrypto.hash.sha3.SHA3_512
import org.kotlincrypto.hash.sha3.SHAKE256

class KeyAgreement {
    val parameter: KyberParameter
    val keypair: KyberKEMKeyPair
    constructor(kemKeyPair: KyberKEMKeyPair) {
        this.parameter = kemKeyPair.encapsulationKey.key.parameter
        this.keypair = kemKeyPair
    }

    fun toCipherText(encryptionKey: KyberEncryptionKey, plainText: ByteArray, randomness: ByteArray): KyberCipherText {
        val decodedKey = KyberMath.byteDecode(encryptionKey.keyBytes, 12)
        val nttKeyVector = Array(parameter.K) { ShortArray(KyberConstants.N) }

        for(i in 0..<parameter.K)
            decodedKey.copyInto(nttKeyVector[i], 0, KyberConstants.N * i, KyberConstants.N * (i + 1))

        val nttSeed = encryptionKey.nttSeed

        val matrix = Array(parameter.K) { Array(parameter.K) { ShortArray(KyberConstants.N) } }
        val randomnessVector = Array(parameter.K) { ShortArray(KyberConstants.N) }
        val noiseVector = Array(parameter.K) { ShortArray(KyberConstants.N) }

        for((n, i) in (0..<parameter.K).withIndex()) {

            randomnessVector[i] = KyberMath.samplePolyCBD(parameter.ETA1, KyberMath.prf(parameter.ETA1, randomness, n.toByte()))
            randomnessVector[i] = KyberMath.NTT(randomnessVector[i])

            noiseVector[i] = KyberMath.samplePolyCBD(parameter.ETA2, KyberMath.prf(parameter.ETA2, randomness, (n + parameter.K).toByte()))

            for(j in 0..<parameter.K) {
                matrix[i][j] = KyberMath.sampleNTT(KyberMath.xof(nttSeed, i.toByte(), j.toByte()))
            }
        }

        val noiseTerm = KyberMath.samplePolyCBD(parameter.ETA2, KyberMath.prf(parameter.ETA2, randomness, ((parameter.K * 2) + 1).toByte()))

        var coefficients = KyberMath.nttMatrixToVectorDot(matrix, randomnessVector, false)

        for(i in 0..<parameter.K) {
            coefficients[i] = KyberMath.invNTT(coefficients[i])
        }

        coefficients = KyberMath.vectorAddition(coefficients, noiseVector)

        val muse = KyberMath.decompress(KyberMath.byteDecode(plainText, 1), 1)

        //START << THIS PART IS BASED FROM FiloSottile/mlkem768

        var constantTerm = ShortArray(KyberConstants.N)
        for(i in 0..<parameter.K) {
            constantTerm = KyberMath.vectorToVectorAdd(constantTerm, KyberMath.multiplyNTTs(nttKeyVector[i], randomnessVector[i]))
        }

        constantTerm = KyberMath.invNTT(constantTerm)
        constantTerm = KyberMath.vectorToVectorAdd(constantTerm, noiseTerm)
        constantTerm = KyberMath.vectorToVectorAdd(constantTerm, muse)

        //END << THIS PART IS BASED FROM FiloSottile/mlkem768

        val encodedCoefficients = ByteArray(32 * (parameter.DU * parameter.K))
        val encodedTerms = ByteArray(32 * parameter.DV)

        for(i in 0..<parameter.K) {
            KyberMath.byteEncode(KyberMath.compress(coefficients[i], parameter.DU), parameter.DU).copyInto(encodedCoefficients, i * 32 * parameter.DU)
        }

        KyberMath.byteEncode(KyberMath.compress(constantTerm, parameter.DV), parameter.DV).copyInto(encodedTerms)

        return KyberCipherText(parameter, encodedCoefficients, encodedTerms)
    }

    fun fromCipherText(cipherText: KyberCipherText): ByteArray {
        val coefficients = Array(cipherText.parameter.K) { ShortArray(KyberConstants.N) }

        for (i in 0..<parameter.K) {
            coefficients[i] = KyberMath.decompress(
                KyberMath.byteDecode(
                    cipherText.encodedCoefficients.copyOfRange(
                        i * 32 * parameter.DU,
                        (i + 1) * 32 * parameter.DU),
                    parameter.DU
                ),
                parameter.DU
            )
        }

        val constantTerms = KyberMath.decompress(KyberMath.byteDecode(cipherText.encodedTerms, parameter.DV), parameter.DV)
        val secretVector = KyberMath.byteDecode(keypair.decapsulationKey.key.keyBytes, 12)

        val trueConstantTerm = constantTerms

        for (i in 0..<parameter.K) {
            val subtraction = KyberMath.invNTT(
                KyberMath.multiplyNTTs(
                    secretVector.copyOfRange(
                        i * KyberConstants.N,
                        (i + 1) * KyberConstants.N),
                    KyberMath.NTT(coefficients[i])
                )
            )
            for (j in 0..<KyberConstants.N)
                trueConstantTerm[j] = KyberMath.moduloOf(trueConstantTerm[j] - subtraction[j], KyberConstants.Q)
        }

        return KyberMath.byteEncode(KyberMath.compress(trueConstantTerm, 1), 1)
    }

    fun encapsulate(kyberEncapsulationKey: KyberEncapsulationKey, plainText: ByteArray = SecureRandom.generateSecureBytes(32)): KyberEncapsulationResult {
        if(kyberEncapsulationKey.key.fullBytes.size != ((384 * kyberEncapsulationKey.key.parameter.K) + 32))
            println("Type Check failed!")
        if(!KyberMath.byteEncode(KyberMath.byteDecode(kyberEncapsulationKey.key.keyBytes, 12), 12).contentEquals(kyberEncapsulationKey.key.keyBytes))
            println("Modulus Check failed!")

        val sha3256 = SHA3_256()

        sha3256.update(kyberEncapsulationKey.key.fullBytes)

        val sha3512 = SHA3_512()

        sha3512.update(plainText)
        sha3512.update(sha3256.digest())

        val sharedKeyAndRandomness = sha3512.digest()

        val cipherText = toCipherText(kyberEncapsulationKey.key, plainText, sharedKeyAndRandomness.copyOfRange(32, 64))

        return KyberEncapsulationResult(sharedKeyAndRandomness.copyOfRange(0, 32), cipherText)
    }

    fun decapsulate(cipherText: KyberCipherText): ByteArray {
        val encryptionKey = keypair.decapsulationKey.encryptionKey
        val encryptionHash = keypair.decapsulationKey.hash
        val rejections = keypair.decapsulationKey.randomSeed

        val recoveredPlainText = fromCipherText(cipherText)

        val sha3512 = SHA3_512()

        sha3512.update(recoveredPlainText)
        sha3512.update(encryptionHash)

        val KprimeAndRandomprime = sha3512.digest()

        val shake256 = SHAKE256(32)

        shake256.update(rejections)
        shake256.update(cipherText.fullBytes)

        val Kbar = shake256.digest()

        var Kprime = KprimeAndRandomprime.copyOfRange(0, 32)
        val cprime = toCipherText(encryptionKey, recoveredPlainText, KprimeAndRandomprime.copyOfRange(32, 64))

        if(!cipherText.fullBytes.contentEquals(cprime.fullBytes))
            Kprime = Kbar

        return Kprime
    }
}