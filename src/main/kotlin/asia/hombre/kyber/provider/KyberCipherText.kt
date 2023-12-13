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

import asia.hombre.kyber.spec.KyberParameterSpec
import asia.hombre.kyber.util.KyberKeyUtil
import org.bouncycastle.asn1.*
import java.io.*
import java.math.BigInteger
import java.security.InvalidKeyException
import java.security.KeyRep
import java.security.ProviderException
import java.security.PublicKey
import java.util.*

class KyberCipherText: PublicKey, Serializable {
    val serialVersionUID = 162829752227350468L

    private lateinit var c: ByteArray
    val cipherTextBytes: ByteArray
    private var encodedKey: ByteArray? = null

    private var p: BigInteger
    private var g: BigInteger

    private var l = 0

    @Throws(InvalidKeyException::class)
    constructor(c: ByteArray, p: BigInteger, g: BigInteger): this(c, p, g, c.size)

    @Throws(InvalidKeyException::class)
    constructor(c: ByteArray, p: BigInteger, g: BigInteger, l: Int) {
        this.c = c.clone()
        this.p = p
        this.g = g
        this.l = l
        try {
            cipherTextBytes = ASN1InputStream(getC()).readAllBytes()
            encodedKey = getEncoded()
        } catch (e: IOException) {
            throw ProviderException("Cannot produce ASN.1 encoding", e)
        }
    }

    @Throws(InvalidKeyException::class)
    constructor(encodedKey: ByteArray) {
        val inStream: InputStream = ByteArrayInputStream(encodedKey)
        try {
            val derParser = DERExternalParser(ASN1StreamParser(inStream))
            val derKeyVal = DERSequence(derParser.readObject()).parser()

            /*
             * Parse the algorithm identifier
             */
            val algid = DERSequence(derKeyVal.readObject()).parser()

            val oid = algid.readObject() as ASN1ObjectIdentifier
            val params = DERSequence(algid.readObject()).parser()

            this.p = (params.readObject() as ASN1Integer).value
            this.g = (params.readObject() as ASN1Integer).value
            this.l = 0

            val lTemp = params.readObject()

            // Private-value length is OPTIONAL
            if (lTemp !is ASN1Null) {
                this.l = (lTemp as ASN1Integer).intValueExact()
            }

            if (params.readObject() !is ASN1Null) {
                throw InvalidKeyException("Extra parameter data")
            }

            /*
             * Parse the key
             */
            cipherTextBytes = (derKeyVal.readObject() as ASN1BitString).bytes
            parseKeyBits()
            if (derKeyVal.readObject() !is ASN1Null) {
                throw InvalidKeyException("Excess key data")
            }
            this.encodedKey = ByteArray(encodedKey.size)
            System.arraycopy(encodedKey, 0, this.encodedKey, 0, encodedKey.size)
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
        if(this.encodedKey == null) {
            val outputStream = ByteArrayOutputStream()
            val derSequenceGenerator = DERSequenceGenerator(outputStream)

            derSequenceGenerator.addObject(ASN1ObjectIdentifier(Kyber.OID_KYBER))

            val paramsByteStream = ByteArrayOutputStream()
            val paramsSequenceGenerator = DERSequenceGenerator(paramsByteStream)

            paramsSequenceGenerator.addObject(ASN1Integer(p))
            paramsSequenceGenerator.addObject(ASN1Integer(g))
            if (l != 0)
                paramsSequenceGenerator.addObject(ASN1Integer(l.toLong()))

            paramsSequenceGenerator.close()

            derSequenceGenerator.addObject(ASN1Sequence.fromByteArray(paramsByteStream.toByteArray()))

            derSequenceGenerator.close()

            this.encodedKey = outputStream.toByteArray()
        }

        val newKey = ByteArray(encodedKey!!.size)
        System.arraycopy(encodedKey, 0, newKey, 0, encodedKey!!.size)
        return newKey
    }

    fun getC(): ByteArray {
        return c.clone()
    }

    fun getParams(): KyberParameterSpec {
        return KyberParameterSpec(p, g, l)
    }

    @Throws(InvalidKeyException::class)
    private fun parseKeyBits() {
        try {
            val `in` = ASN1InputStream(this.cipherTextBytes)
            val rawArray: ByteArray = `in`.readAllBytes()
            c = ByteArray(rawArray.size - 4)
            System.arraycopy(rawArray, 4, c, 0, rawArray.size - 4)
            l = c.size
        } catch (e: IOException) {
            throw InvalidKeyException(
                "Error parsing key encoding: $e"
            )
        }
    }

    override fun hashCode(): Int {
        return Objects.hash(c, p, g)
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) {
            return true
        }
        if (other !is KyberCipherText) {
            return false
        }
        val otherParams: KyberParameterSpec = other.getParams()
        return KyberKeyUtil.constantTimeCompare(c,
            other.getC()) === 0
                && p.compareTo(otherParams.p) == 0
                && g.compareTo(otherParams.g) == 0
    }

    @Throws(ObjectStreamException::class)
    private fun writeReplace(): Any {
        return KeyRep(
            KeyRep.Type.PUBLIC,
            getAlgorithm(),
            getFormat(),
            getEncoded()
        )
    }
}