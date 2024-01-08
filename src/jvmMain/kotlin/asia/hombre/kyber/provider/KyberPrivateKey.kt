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

import asia.hombre.kyber.`interface`.BaseKyberPrivateKey
import asia.hombre.kyber.spec.KyberParameterSpec
import asia.hombre.kyber.util.KyberKeyUtil
import org.bouncycastle.asn1.*
import java.io.*
import java.math.BigInteger
import java.security.InvalidKeyException
import java.security.KeyRep
import java.util.*

class KyberPrivateKey: BaseKyberPrivateKey, Serializable {
    override val serialVersionUID = 539164407768758014L
    lateinit var kyberKeySize: Kyber.KeySize
    private val PKCS8_VERSION = BigInteger.ZERO

    override lateinit var x: ByteArray
    override var keySize: Int = 0
    override val params: KyberParameterSpec

    private var key: ByteArray
    private var encodedKey: ByteArray? = null

    private var l: Int = 0

    @Throws(InvalidKeyException::class)
    constructor(x: ByteArray, p: BigInteger, g: BigInteger): this(x, p, g, x.size * 8)

    @Throws(InvalidKeyException::class)
    constructor(x: ByteArray, p: BigInteger, g: BigInteger, l: Int) {
        kyberKeySize = KyberKeyUtil.getKyberKeySizeFromPrivateKey(x.size)
        this.keySize = kyberKeySize.length
        this.x = x.clone()
        params = KyberParameterSpec(p, g, l)
        try {
            key = ASN1InputStream(this.x).readAllBytes()
            encodedKey = getEncoded()
        } catch (e: IOException) {
            throw e//ProviderException("Cannot produce ASN.1 encoding", e)
        }
    }

    @Throws(InvalidKeyException::class)
    constructor(encodedKey: ByteArray) {
        val inStream: InputStream = ByteArrayInputStream(encodedKey)
        try {
            val stream = ASN1InputStream(inStream)

            val keySequence = (stream.readObject() as DERSequence).parser()

            val parsedVersion: BigInteger = (keySequence.readObject() as ASN1Integer).value

            if (parsedVersion != PKCS8_VERSION) {
                throw IOException(
                    "version mismatch: (supported: "
                            + PKCS8_VERSION + ", parsed: "
                            + parsedVersion
                )
            }

            val algid = (keySequence.readObject() as DERSequence).parser()

            val derInStream = algid as ASN1InputStream
            //val oid: ObjectIdentifier = derInStream.oid ?: throw InvalidKeyException("Null OID")
            if (derInStream.available() == 0) {
                throw InvalidKeyException("Parameters missing")
            }

            val params = (derInStream.readObject() as DERSequence).parser()

            val p = (params.readObject() as ASN1Integer).value
            val g = (params.readObject() as ASN1Integer).value
            this.l = 0

            val lTemp = params.readObject()

            // Private-value length is OPTIONAL
            if (lTemp !is ASN1Null) {
                this.l = (lTemp as ASN1Integer).intValueExact()
            }

            this.params = KyberParameterSpec(p, g, this.l)

            if (params.readObject() !is ASN1Null) {
                throw InvalidKeyException("Extra parameter data")
            }

            key = (algid.readObject() as DEROctetString).octets
            parseKeyBits()
            this.encodedKey = ByteArray(encodedKey.size)
            System.arraycopy(encodedKey, 0, this.encodedKey!!, 0, encodedKey.size)
        } catch (e: Exception) {
            throw InvalidKeyException("Error parsing key encoding", e)
        }
    }

    override fun getFormat(): String {
        return "PKCS#8"
    }

    override fun getAlgorithm(): String {
        return "Kyber"
    }

    @Synchronized
    override fun getEncoded(): ByteArray {
        if (encodedKey == null) {
            val outputStreamBuffer = ByteArrayOutputStream()
            val bufferSequenceGenerator = DERSequenceGenerator(outputStreamBuffer)

            bufferSequenceGenerator.addObject(ASN1Integer(PKCS8_VERSION))

            val outputStream = ByteArrayOutputStream()
            val derSequenceGenerator = DERSequenceGenerator(outputStream)

            derSequenceGenerator.addObject(ASN1ObjectIdentifier(Kyber.OID_KYBER))

            val paramsByteStream = ByteArrayOutputStream()
            val paramsSequenceGenerator = DERSequenceGenerator(paramsByteStream)

            paramsSequenceGenerator.addObject(ASN1Integer(this.params.p))
            paramsSequenceGenerator.addObject(ASN1Integer(this.params.g))
            if (l != 0)
                paramsSequenceGenerator.addObject(ASN1Integer(l.toLong()))

            paramsSequenceGenerator.close()

            derSequenceGenerator.addObject(ASN1Sequence.fromByteArray(paramsByteStream.toByteArray()))

            derSequenceGenerator.close()

            bufferSequenceGenerator.addObject(DERSequence.fromByteArray(outputStream.toByteArray()))
            bufferSequenceGenerator.addObject(DEROctetString(key))

            bufferSequenceGenerator.close()

            this.encodedKey = outputStreamBuffer.toByteArray()
        }

        val newKey = ByteArray(encodedKey!!.size)
        System.arraycopy(encodedKey!!, 0, newKey, 0, encodedKey!!.size)
        return newKey
    }

    @Throws(InvalidKeyException::class)
    private fun parseKeyBits() {
        try {
            val `in` = ASN1InputStream(key)
            val rawArray: ByteArray = `in`.readAllBytes()
            x = ByteArray(rawArray.size - 4)
            System.arraycopy(rawArray, 4, x, 0, rawArray.size - 4)
            kyberKeySize = KyberKeyUtil.getKyberKeySizeFromPrivateKey(x.size)
            keySize = kyberKeySize.length
            l = x.size
        } catch (e: IOException) {
            throw InvalidKeyException(
                "Error parsing key encoding: " + e.message
            )
        }
    }

    override fun hashCode(): Int {
        return Objects.hash(x, this.params.p, this.params.g)
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) {
            return true
        }
        if (other !is BaseKyberPrivateKey) {
            return false
        }
        val otherParams: KyberParameterSpec = other.params
        return KyberKeyUtil.constantTimeCompare(x, other.x) == 0 &&
                (this.params.p.compareTo(otherParams.p) == 0) &&
                (this.params.g.compareTo(otherParams.g) == 0)
    }

    @Throws(ObjectStreamException::class)
    private fun writeReplace(): Any {
        return KeyRep(
            KeyRep.Type.PRIVATE,
            algorithm,
            format,
            getEncoded()
        )
    }
}