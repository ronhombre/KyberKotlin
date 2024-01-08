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
package asia.hombre.kyber.provider

import asia.hombre.kyber.exception.NotKyberParameterSpecException
import asia.hombre.kyber.exception.NotKyberPrivateKeyException
import asia.hombre.kyber.security.KyberINDCPA
import asia.hombre.kyber.spec.KyberParameterSpec
import asia.hombre.kyber.util.KyberKeyUtil
import org.kotlincrypto.hash.sha3.SHAKE256
import java.math.BigInteger
import java.security.*
import java.security.spec.AlgorithmParameterSpec
import javax.crypto.KeyAgreementSpi
import javax.crypto.SecretKey
import javax.crypto.ShortBufferException

class KyberKeyAgreement : KeyAgreementSpi() {
    private lateinit var kyberKeySize: Kyber.KeySize
    private var init_p: BigInteger? = null
    private var init_g: BigInteger? = null
    private var x = ByteArray(0) // the private value

    private var y = ByteArray(0)
    var kyberCipherText: KyberCipherText? = null
    private val rnd = ByteArray(Kyber.Params.CPAPKE_BYTES)


    @Throws(InvalidKeyException::class)
    fun engineInit(key: Key) {
        if(key is KyberPrivateKey) {
            engineInit(key, KyberParameterSpec(Kyber.Params.DEFAULT_P, Kyber.Params.DEFAULT_G, key.keySize), SecureRandom.getInstanceStrong())
        } else throw NotKyberPrivateKeyException()
    }

    @Throws(InvalidKeyException::class)
    override fun engineInit(key: Key, random: SecureRandom) {
        if(key is KyberPrivateKey) {
            engineInit(key, KyberParameterSpec(Kyber.Params.DEFAULT_P, Kyber.Params.DEFAULT_G, key.keySize), random)
        } else throw NotKyberPrivateKeyException()
    }

    @Throws(InvalidKeyException::class, InvalidAlgorithmParameterException::class)
    override fun engineInit(key: Key, params: AlgorithmParameterSpec, random: SecureRandom) {
        if (params !is KyberParameterSpec) throw NotKyberParameterSpecException()
        if (key !is KyberPrivateKey) throw NotKyberPrivateKeyException()

        init_p = null
        init_g = null

        random.nextBytes(rnd)

        val kyberPrivKey: KyberPrivateKey = key

        kyberKeySize = KyberKeyUtil.getKyberKeySizeFromPrivateKey(kyberPrivKey.x.size)
        // check if private key parameters are compatible with
        // initialized ones
        if (params != null) {
            init_p = params.p
            init_g = params.g
        }
        val priv_p: BigInteger = kyberPrivKey.params.p
        val priv_g: BigInteger = kyberPrivKey.params.g
        if ((init_p != null) && init_p != priv_p)
            throw InvalidKeyException("Incompatible parameters")
        if ((init_g != null) && init_g != priv_g)
            throw InvalidKeyException("Incompatible parameters")

        init_p = priv_p
        init_g = priv_g

        // store the x value
        x = kyberPrivKey.x
    }

    @Throws(InvalidKeyException::class, IllegalStateException::class)
    public override fun engineDoPhase(key: Key, lastPhase: Boolean): Key? {
        if (init_p == null || init_g == null) {
            throw IllegalStateException("Not initialized")
        }
        if (key is KyberPublicKey) {
            // check if public key parameters are compatible with
            // initialized ones
            val pub_p: BigInteger = key.params.p
            val pub_g: BigInteger = key.params.g
            if (pub_p != null && init_p != pub_p) {
                throw InvalidKeyException("Incompatible parameters")
            }
            if (pub_g != null && init_g != pub_g) {
                throw InvalidKeyException("Incompatible parameters")
            }

            // validate the Kyber public key
            KyberKeyUtil.validate(key)

            // store the y value
            y = key.y

            // we've received a public key (from one of the other parties),
            // so we are ready to create the secret, which may be an
            // intermediate secret, in which case we wrap it into a
            // Kyber public key object and return it.
            if (lastPhase == true) {
                val sharedSecret = engineGenerateSecret()

                return KyberSharedSecretKey(kyberKeySize, sharedSecret)
            } else {
                return null
            }
        } else if (key is KyberCipherText) {
            return decrypt(kyberKeySize, key)
        }
        throw InvalidKeyException("Expected a KyberPublicKey or KyberCipherText")
    }

    @Throws(IllegalStateException::class)
    override fun engineGenerateSecret(): ByteArray {
        val sharedSecret = ByteArray(Kyber.Params.CPAPKE_BYTES)
        try {
            engineGenerateSecret(sharedSecret, 0)
        } catch (sbe: ShortBufferException) {
            // should never happen since length are identical
        }
        return sharedSecret
    }

    @Throws(IllegalStateException::class, ShortBufferException::class)
    override fun engineGenerateSecret(sharedSecret: ByteArray?, offset: Int): Int {
        val kyberEncrypted = encrypt()
        val tempSecret: ByteArray = kyberEncrypted.first.secretKeyBytes
        System.arraycopy(tempSecret, 0, sharedSecret!!, 0, tempSecret.size)
        kyberCipherText = kyberEncrypted.second
        return Kyber.Params.CPAPKE_BYTES
    }

    @Throws(IllegalStateException::class, NoSuchAlgorithmException::class, InvalidKeyException::class)
    override fun engineGenerateSecret(algorithm: String?): SecretKey {
        throw NoSuchAlgorithmException("Not implemented")
    }

    fun decrypt(kyberKeySize: Kyber.KeySize, cipherText: KyberCipherText): KyberSharedSecretKey {
        return when(kyberKeySize) {
            Kyber.KeySize.VARIANT_512 ->
                decryptGeneric(cipherText,
                    Kyber.Params.INDCPA_PRIVATE_KEY_BYTES_512,
                    Kyber.Params.INDCPA_PUBLIC_KEY_BYTES_512,
                    Kyber.Params.PRIVATE_KEY_BYTES_512
                )
            Kyber.KeySize.VARIANT_768 ->
                decryptGeneric(cipherText,
                    Kyber.Params.INDCPA_PRIVATE_KEY_BYTES_768,
                    Kyber.Params.INDCPA_PUBLIC_KEY_BYTES_768,
                    Kyber.Params.PRIVATE_KEY_BYTES_768
                )
            Kyber.KeySize.VARIANT_1024 ->
                decryptGeneric(cipherText,
                    Kyber.Params.INDCPA_PRIVATE_KEY_BYTES_1024,
                    Kyber.Params.INDCPA_PUBLIC_KEY_BYTES_1024,
                    Kyber.Params.PRIVATE_KEY_BYTES_1024
                )
        }
    }

    private fun decryptGeneric(cipherText: KyberCipherText, indcpaPrivateKeyLength: Int, indcpaPublicKeyLength: Int, privateKeyLength: Int): KyberSharedSecretKey {
        val cipher = cipherText.getC()
        val privateKey = x
        val paramsK = this.kyberKeySize.K
        var sharedSecretFixedLength: ByteArray
        val indcpaPrivateKey = ByteArray(indcpaPrivateKeyLength)
        System.arraycopy(privateKey, 0, indcpaPrivateKey, 0, indcpaPrivateKey.size)
        val publicKey = ByteArray(indcpaPublicKeyLength)
        System.arraycopy(privateKey, indcpaPrivateKey.size, publicKey, 0, publicKey.size)
        val buf: ByteArray = KyberINDCPA.decrypt(cipher, indcpaPrivateKey, paramsK)
        val ski: Int = privateKeyLength - 2 * Kyber.Params.CPAPKE_BYTES
        val newBuf = ByteArray(buf.size + Kyber.Params.CPAPKE_BYTES)
        System.arraycopy(buf, 0, newBuf, 0, buf.size)
        System.arraycopy(privateKey, ski, newBuf, buf.size, Kyber.Params.CPAPKE_BYTES)
        val md512: MessageDigest = Kyber.getInstance().sha3_512
        val kr = md512.digest(newBuf)
        val subKr = ByteArray(kr.size - Kyber.Params.CPAPKE_BYTES)
        System.arraycopy(kr, Kyber.Params.CPAPKE_BYTES, subKr, 0, subKr.size)
        val cmp: ByteArray = KyberINDCPA.encrypt(buf, publicKey, subKr, paramsK)
        this.kyberCipherText = KyberCipherText(cmp, Kyber.Params.DEFAULT_P, Kyber.Params.DEFAULT_G)

        val fail = KyberKeyUtil.constantTimeCompare(cipher, cmp).toByte()
        val md: MessageDigest = Kyber.getInstance().sha3_256
        val krh = md.digest(cipher)
        var index: Int = privateKeyLength - Kyber.Params.CPAPKE_BYTES
        for (i in 0 until Kyber.Params.CPAPKE_BYTES) {
            kr[i] =
                ((kr[i].toInt() and 0xFF) xor ((fail.toInt() and 0xFF) and ((kr[i].toInt() and 0xFF) xor (privateKey[index].toInt() and 0xFF)))).toByte()
            index += 1
        }
        val tempBuf = ByteArray(Kyber.Params.CPAPKE_BYTES + krh.size)
        System.arraycopy(kr, 0, tempBuf, 0, Kyber.Params.CPAPKE_BYTES)
        System.arraycopy(krh, 0, tempBuf, Kyber.Params.CPAPKE_BYTES, krh.size)
        val xof = SHAKE256(Kyber.Params.SHARED_SECRET_BYTES)
        xof.update(tempBuf)
        sharedSecretFixedLength = xof.digest()

        return KyberSharedSecretKey(this.kyberKeySize, sharedSecretFixedLength)
    }

    private fun encrypt(): Pair<KyberSharedSecretKey, KyberCipherText> {
        return try {
            encryptGeneric(rnd, y)
        } catch (ex: Exception) {
            throw ex//KyberSecretKeyGenerationException()
        }
    }

    private fun encryptGeneric(variantBytes: ByteArray, publicKeyBytes: ByteArray): Pair<KyberSharedSecretKey, KyberCipherText> {
        val verifiedVariantBytes = verifyVariant(variantBytes)
        val paramsK = this.kyberKeySize.K
        val sharedSecret: ByteArray
        val md: MessageDigest = Kyber.getInstance().sha3_256
        val buf1 = md.digest(verifiedVariantBytes)
        val buf2 = md.digest(publicKeyBytes)
        val buf3 = ByteArray(buf1.size + buf2.size)
        System.arraycopy(buf1, 0, buf3, 0, buf1.size)
        System.arraycopy(buf2, 0, buf3, buf1.size, buf2.size)
        val md512: MessageDigest = Kyber.getInstance().sha3_512
        val kr = md512.digest(buf3)
        val subKr = ByteArray(kr.size - Kyber.Params.CPAPKE_BYTES)
        System.arraycopy(kr, Kyber.Params.CPAPKE_BYTES, subKr, 0, subKr.size)
        val ciphertext: ByteArray = KyberINDCPA.encrypt(buf1, publicKeyBytes, subKr, paramsK)
        val krc = md.digest(ciphertext)
        val newKr = ByteArray(Kyber.Params.CPAPKE_BYTES + krc.size)
        System.arraycopy(kr, 0, newKr, 0, Kyber.Params.CPAPKE_BYTES)
        System.arraycopy(krc, 0, newKr, Kyber.Params.CPAPKE_BYTES, krc.size)
        val xof = SHAKE256(Kyber.Params.SHARED_SECRET_BYTES)
        xof.update(newKr)
        sharedSecret = xof.digest()
        //     System.arraycopy(ciphertext, 0, ciphertextFixedLength, 0, ciphertext.length);
        //   System.arraycopy(sharedSecret, 0, sharedSecretFixedLength, 0, sharedSecret.length);

        return Pair(KyberSharedSecretKey(this.kyberKeySize, sharedSecret), KyberCipherText(ciphertext, Kyber.Params.DEFAULT_P, Kyber.Params.DEFAULT_G))
    }

    @Throws(IllegalArgumentException::class)
    private fun verifyVariant(variant: ByteArray): ByteArray {
        if (variant.size > Kyber.Params.CPAPKE_BYTES) {
            throw IllegalArgumentException("Byte array exceeds allowable size of " + Kyber.Params.CPAPKE_BYTES + " bytes")
        } else if (variant.size < Kyber.Params.CPAPKE_BYTES) { //TODO: Verify if you really need to set bytes to 0
            val tempData = ByteArray(Kyber.Params.CPAPKE_BYTES)
            System.arraycopy(variant, 0, tempData, 0, variant.size)
            val emptyBytes = ByteArray(Kyber.Params.CPAPKE_BYTES - variant.size)
            for (i in emptyBytes.indices) {
                emptyBytes[i] = 0.toByte()
            }
            System.arraycopy(emptyBytes, 0, tempData, variant.size, emptyBytes.size)
            return tempData
        }
        return variant
    }
}