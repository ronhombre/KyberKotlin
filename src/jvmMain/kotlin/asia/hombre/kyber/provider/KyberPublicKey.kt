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

import asia.hombre.kyber.`interface`.BaseKyberPublicKey
import asia.hombre.kyber.spec.KyberParameterSpec
import asia.hombre.kyber.util.KyberKeyUtil
import org.bouncycastle.asn1.*
import java.io.*
import java.math.BigInteger
import java.security.InvalidKeyException
import java.security.KeyRep
import java.util.*

class KyberPublicKey: BaseKyberPublicKey, Serializable {
    override val serialVersionUID = 2748565237750324982L

    // the public key
    override lateinit var y: ByteArray
    override var params: KyberParameterSpec

    lateinit var kyberKeySize: Kyber.KeySize
    override var keySize: Int = 0

    private var key: ByteArray
    private var encodedKey: ByteArray?

    private var l = 0

    @Throws(InvalidKeyException::class)
    constructor(y: ByteArray, p: BigInteger, g: BigInteger): this(y, p, g, y.size)

    @Throws(InvalidKeyException::class)
    constructor(y: ByteArray, p: BigInteger, g: BigInteger, l: Int) {
        kyberKeySize = KyberKeyUtil.getKyberKeySizeFromPublicKey(y.size)
        this.keySize = kyberKeySize.length
        this.y = y.clone()
        params = KyberParameterSpec(p, g, l)
        try {
            key = ASN1InputStream(this.y).readAllBytes()
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

            val algid = (stream.readObject() as DERSequence).parser()

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

            key = (algid.readObject() as DERBitString).bitStream.readAllBytes()
            parseKeyBits() //TODO: Add excess checker
            this.encodedKey = ByteArray(encodedKey.size)
            System.arraycopy(encodedKey, 0, this.encodedKey!!, 0, encodedKey.size)
        } catch (e: IOException) {
            throw InvalidKeyException("Error parsing key encoding", e)
        } catch (e: NumberFormatException) {
            throw InvalidKeyException("Error parsing key encoding", e)
        }
    }

    override fun getFormat(): String {
        return "X.509"
    }

    override fun getAlgorithm(): String {
        return "Kyber"
    }

    @Synchronized
    override fun getEncoded(): ByteArray {
        if(encodedKey == null) {
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

            derSequenceGenerator.addObject(DERSequence.fromByteArray(paramsByteStream.toByteArray()))

            derSequenceGenerator.close()

            val outputStreamBuffer = ByteArrayOutputStream()
            val bufferSequenceGenerator = DERSequenceGenerator(outputStreamBuffer)

            bufferSequenceGenerator.addObject(DERSequence.fromByteArray(outputStream.toByteArray()))
            bufferSequenceGenerator.addObject(DERBitString(key))

            bufferSequenceGenerator.close()

            val encodedOutputStream = ByteArrayOutputStream()
            val encodedSequenceGenerator = DERSequenceGenerator(encodedOutputStream)

            encodedSequenceGenerator.addObject(DERSequence.fromByteArray(outputStreamBuffer.toByteArray()))

            encodedSequenceGenerator.close()

            this.encodedKey = encodedOutputStream.toByteArray()
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
            y = ByteArray(rawArray.size - 4)
            System.arraycopy(rawArray, 4, y, 0, rawArray.size - 4)
            kyberKeySize = KyberKeyUtil.getKyberKeySizeFromPublicKey(y.size)
            keySize = kyberKeySize.length
            l = y.size
        } catch (e: IOException) {
            throw InvalidKeyException(
                "Error parsing key encoding: $e"
            )
        }
    }

    override fun hashCode(): Int {
        return Objects.hash(y, this.params.p, this.params.g)
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) {
            return true
        }
        if (other !is KyberPublicKey) {
            return false
        }
        val otherParams: KyberParameterSpec = other.params
        return KyberKeyUtil.constantTimeCompare(y, other.y) == 0 &&
                this.params.p.compareTo(otherParams.p) == 0 &&
                this.params.g.compareTo(otherParams.g) == 0
    }

    @Throws(ObjectStreamException::class)
    private fun writeReplace(): Any {
        return KeyRep(
            KeyRep.Type.PUBLIC,
            algorithm,
            format,
            getEncoded()
        )
    }
}