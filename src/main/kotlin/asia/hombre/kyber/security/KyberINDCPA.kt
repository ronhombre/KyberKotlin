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
package asia.hombre.kyber.security

import asia.hombre.kyber.math.Polynomial
import asia.hombre.kyber.provider.Kyber
import asia.hombre.kyber.provider.KyberUniformRandom
import org.kotlincrypto.hash.sha3.SHAKE128
import org.kotlincrypto.hash.sha3.SHAKE256
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.*

internal class KyberINDCPA {
    companion object {
        fun packPublicKey(publicKey: Array<ShortArray>, seed: ByteArray, paramsK: Int): ByteArray {
            val initialArray: ByteArray = Polynomial.polyVectorToBytes(publicKey, paramsK)
            val packedPublicKey: ByteArray
            when (paramsK) {
                2 -> {
                    packedPublicKey = ByteArray(Kyber.Params.INDCPA_PUBLIC_KEY_BYTES_512)
                    System.arraycopy(initialArray, 0, packedPublicKey, 0, initialArray.size)
                    System.arraycopy(seed, 0, packedPublicKey, initialArray.size, seed.size)
                }

                3 -> {
                    packedPublicKey = ByteArray(Kyber.Params.INDCPA_PUBLIC_KEY_BYTES_768)
                    System.arraycopy(initialArray, 0, packedPublicKey, 0, initialArray.size)
                    System.arraycopy(seed, 0, packedPublicKey, initialArray.size, seed.size)
                }

                else -> {
                    packedPublicKey = ByteArray(Kyber.Params.INDCPA_PUBLIC_KEY_BYTES_1024)
                    System.arraycopy(initialArray, 0, packedPublicKey, 0, initialArray.size)
                    System.arraycopy(seed, 0, packedPublicKey, initialArray.size, seed.size)
                }
            }
            return packedPublicKey
        }

        fun unpackPublicKey(packedPublicKey: ByteArray, paramsK: Int): UnpackedKyberPublicKey {
            return when (paramsK) {
                2 -> {
                    UnpackedKyberPublicKey(
                        Arrays.copyOfRange(
                            packedPublicKey,
                            Kyber.Params.POLY_VECTOR_BYTES_512,
                            packedPublicKey.size
                        ),
                        Polynomial.polyVectorFromBytes(
                            Arrays.copyOfRange(
                                packedPublicKey,
                                0,
                                Kyber.Params.POLY_VECTOR_BYTES_512
                            ), paramsK
                        ))
                }

                3 -> {
                    UnpackedKyberPublicKey(
                        Arrays.copyOfRange(
                            packedPublicKey,
                            Kyber.Params.POLY_VECTOR_BYTES_768,
                            packedPublicKey.size
                        ),
                        Polynomial.polyVectorFromBytes(
                            Arrays.copyOfRange(
                                packedPublicKey,
                                0,
                                Kyber.Params.POLY_VECTOR_BYTES_768
                            ), paramsK
                        )
                    )
                }

                else -> {
                    UnpackedKyberPublicKey(
                        Arrays.copyOfRange(
                            packedPublicKey,
                            Kyber.Params.POLY_VECTOR_BYTES_1024,
                            packedPublicKey.size
                        ),
                        Polynomial.polyVectorFromBytes(
                            Arrays.copyOfRange(
                                packedPublicKey,
                                0,
                                Kyber.Params.POLY_VECTOR_BYTES_1024
                            ), paramsK
                        )
                    )
                }
            }
        }

        fun packPrivateKey(privateKey: Array<ShortArray>, paramsK: Int): ByteArray {
            return Polynomial.polyVectorToBytes(privateKey, paramsK)
        }

        fun unpackPrivateKey(packedPrivateKey: ByteArray, paramsK: Int): Array<ShortArray> {
            return Polynomial.polyVectorFromBytes(packedPrivateKey, paramsK)
        }

        fun packCiphertext(b: Array<ShortArray>, v: ShortArray, paramsK: Int): ByteArray {
            val bCompress: ByteArray = Polynomial.compressPolyVector(b, paramsK)
            val vCompress: ByteArray = Polynomial.compressPoly(v, paramsK)
            val returnArray = ByteArray(bCompress.size + vCompress.size)
            System.arraycopy(bCompress, 0, returnArray, 0, bCompress.size)
            System.arraycopy(vCompress, 0, returnArray, bCompress.size, vCompress.size)
            return returnArray
        }

        fun unpackCiphertext(c: ByteArray, paramsK: Int): UnpackedKyberCipherText {
            val bpc: ByteArray
            val vc: ByteArray
            bpc = when (paramsK) {
                2 -> ByteArray(Kyber.Params.POLY_VECTOR_COMPRESSED_BYTES_512)
                3 -> ByteArray(Kyber.Params.POLY_VECTOR_COMPRESSED_BYTES_768)
                else -> ByteArray(Kyber.Params.POLY_VECTOR_COMPRESSED_BYTES_1024)
            }
            System.arraycopy(c, 0, bpc, 0, bpc.size)
            vc = ByteArray(c.size - bpc.size)
            System.arraycopy(c, bpc.size, vc, 0, vc.size)

            return UnpackedKyberCipherText(
                Polynomial.decompressPolyVector(bpc, paramsK),
                Polynomial.decompressPoly(vc, paramsK)
            )
        }

        fun generateUniform(uniformRandom: KyberUniformRandom, buf: ByteArray, bufl: Int, l: Int) {
            val uniformR = ShortArray(Kyber.Params.POLY_BYTES)
            var d1: Int
            var d2: Int
            var uniformI = 0 // Always start at 0
            var j = 0
            while (uniformI < l && j + 3 <= bufl) {
                d1 = ((buf[j].toInt() and 0xFF) shr 0 or ((buf[j + 1].toInt() and 0xFF) shl 8) and 0xFFF)
                d2 = ((buf[j + 1].toInt() and 0xFF) shr 4 or ((buf[j + 2].toInt() and 0xFF) shl 4) and 0xFFF)
                j += 3
                if (d1 < Kyber.Params.Q) {
                    uniformR[uniformI] = d1.toShort()
                    uniformI++
                }
                if (uniformI < l && d2 < Kyber.Params.Q) {
                    uniformR[uniformI] = d2.toShort()
                    uniformI++
                }
            }
            uniformRandom.uniformI = uniformI
            uniformRandom.uniformR = uniformR
        }

        fun generateMatrix(seed: ByteArray, transposed: Boolean, paramsK: Int): Array<Array<ShortArray>> {
            val r = Array(paramsK) {
                Array(paramsK) {
                    ShortArray(
                        Kyber.Params.POLY_BYTES
                    )
                }
            }
            var buf: ByteArray
            val uniformRandom = KyberUniformRandom(ShortArray(Kyber.Params.POLY_BYTES), 0)
            val xof = SHAKE128(672)
            for (i in 0 until paramsK) {
                r[i] = Polynomial.generateNewPolyVector(paramsK)
                for (j in 0 until paramsK) {
                    xof.reset()
                    xof.update(seed)
                    val ij = ByteArray(2)
                    if (transposed) {
                        ij[0] = i.toByte()
                        ij[1] = j.toByte()
                    } else {
                        ij[0] = j.toByte()
                        ij[1] = i.toByte()
                    }
                    xof.update(ij)
                    buf = xof.digest()
                    generateUniform(uniformRandom, Arrays.copyOfRange(buf, 0, 504), 504, Kyber.Params.N)
                    var ui: Int = uniformRandom.uniformI
                    r[i][j] = uniformRandom.uniformR
                    while (ui < Kyber.Params.N) {
                        generateUniform(uniformRandom, Arrays.copyOfRange(buf, 504, 672), 168, Kyber.Params.N - ui)
                        val ctrn: Int = uniformRandom.uniformI
                        val missing: ShortArray = uniformRandom.uniformR
                        for (k in ui until Kyber.Params.N) {
                            r[i][j][k] = missing[k - ui]
                        }
                        ui = ui + ctrn
                    }
                }
            }
            return r
        }

        fun generatePRFByteArray(l: Int, key: ByteArray, nonce: Byte): ByteArray {
            var hash: ByteArray
            val xof = SHAKE256(l)
            val newKey = ByteArray(key.size + 1)
            System.arraycopy(key, 0, newKey, 0, key.size)
            newKey[key.size] = nonce
            xof.update(newKey, 0, newKey.size)
            hash = xof.digest()
            return hash
        }

        fun generateKyberKeys(paramsK: Int): Pair<ByteArray, ByteArray> {
            var skpv: Array<ShortArray> = Polynomial.generateNewPolyVector(paramsK)
            var pkpv: Array<ShortArray> = Polynomial.generateNewPolyVector(paramsK)
            var e: Array<ShortArray> = Polynomial.generateNewPolyVector(paramsK)
            val publicSeed = ByteArray(Kyber.Params.CPAPKE_BYTES)
            val noiseSeed = ByteArray(Kyber.Params.CPAPKE_BYTES)
            val h: MessageDigest = Kyber.getInstance().sha3_512
            val sr = SecureRandom.getInstanceStrong()
            sr.nextBytes(publicSeed)
            val fullSeed = h.digest(publicSeed)
            System.arraycopy(fullSeed, 0, publicSeed, 0, Kyber.Params.CPAPKE_BYTES)
            System.arraycopy(fullSeed, Kyber.Params.CPAPKE_BYTES, noiseSeed, 0, Kyber.Params.CPAPKE_BYTES)
            val a = generateMatrix(publicSeed, false, paramsK)
            var nonce = 0.toByte()
            for (i in 0..<paramsK) {
                skpv[i] = Polynomial.getNoisePoly(noiseSeed, nonce, paramsK)
                nonce = (nonce + 1.toByte()).toByte()
            }
            for (i in 0..<paramsK) {
                e[i] = Polynomial.getNoisePoly(noiseSeed, nonce, paramsK)
                nonce = (nonce + 1.toByte()).toByte()
            }
            skpv = Polynomial.polyVectorNTT(skpv, paramsK)
            skpv = Polynomial.polyVectorReduce(skpv, paramsK)
            e = Polynomial.polyVectorNTT(e, paramsK)
            for (i in 0..<paramsK) {
                val temp: ShortArray = Polynomial.polyVectorPointWiseAccMont(a[i], skpv, paramsK)
                pkpv[i] = Polynomial.polyToMont(temp)
            }
            pkpv = Polynomial.polyVectorAdd(pkpv, e, paramsK)
            pkpv = Polynomial.polyVectorReduce(pkpv, paramsK)

            return Pair(packPublicKey(pkpv, publicSeed, paramsK), packPrivateKey(skpv, paramsK))
        }

        fun encrypt(m: ByteArray, publicKey: ByteArray, coins: ByteArray, paramsK: Int): ByteArray {
            var sp: Array<ShortArray> = Polynomial.generateNewPolyVector(paramsK)
            val ep: Array<ShortArray> = Polynomial.generateNewPolyVector(paramsK)
            var bp: Array<ShortArray> = Polynomial.generateNewPolyVector(paramsK)
            val unpackedPublicKey: UnpackedKyberPublicKey = unpackPublicKey(publicKey, paramsK)
            val k: ShortArray = Polynomial.polyFromData(m)
            val at = generateMatrix(
                Arrays.copyOfRange(unpackedPublicKey.seed, 0, Kyber.Params.CPAPKE_BYTES),
                true,
                paramsK
            )
            for (i in 0..<paramsK) {
                sp[i] = Polynomial.getNoisePoly(coins, i.toByte(), paramsK)
                ep[i] = Polynomial.getNoisePoly(coins, (i + paramsK).toByte(), 3)
            }
            val epp: ShortArray = Polynomial.getNoisePoly(coins, (paramsK * 2).toByte(), 3)
            sp = Polynomial.polyVectorNTT(sp, paramsK)
            sp = Polynomial.polyVectorReduce(sp, paramsK)
            for (i in 0..<paramsK) {
                bp[i] = Polynomial.polyVectorPointWiseAccMont(at[i], sp, paramsK)
            }
            var v: ShortArray = Polynomial.polyVectorPointWiseAccMont(unpackedPublicKey.publicKeyPolyvec, sp, paramsK)
            bp = Polynomial.polyVectorInvNTTMont(bp, paramsK)
            v = Polynomial.polyInvNTTMont(v)
            bp = Polynomial.polyVectorAdd(bp, ep, paramsK)
            v = Polynomial.polyAdd(Polynomial.polyAdd(v, epp), k)
            bp = Polynomial.polyVectorReduce(bp, paramsK)
            return packCiphertext(bp, Polynomial.polyReduce(v), paramsK)
        }

        fun decrypt(packedCipherText: ByteArray, privateKey: ByteArray, paramsK: Int): ByteArray {
            val unpackedCipherText: UnpackedKyberCipherText = unpackCiphertext(packedCipherText, paramsK)
            var bp: Array<ShortArray> = unpackedCipherText.bp
            val v: ShortArray = unpackedCipherText.v
            val unpackedPrivateKey = unpackPrivateKey(privateKey, paramsK)
            bp = Polynomial.polyVectorNTT(bp, paramsK)
            var mp: ShortArray = Polynomial.polyVectorPointWiseAccMont(unpackedPrivateKey, bp, paramsK)
            mp = Polynomial.polyInvNTTMont(mp)
            mp = Polynomial.polySub(v, mp)
            mp = Polynomial.polyReduce(mp)
            return Polynomial.polyToMsg(mp)
        }
    }
}