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

import asia.hombre.kyber.exception.KyberKeyDecodingException
import asia.hombre.kyber.`interface`.BaseKyberPublicKey
import asia.hombre.kyber.spec.KyberParameterSpec
import org.bouncycastle.asn1.*
import java.io.ByteArrayOutputStream
import java.io.Serializable
import java.security.InvalidKeyException

class KyberSharedSecretKey: BaseKyberPublicKey, Serializable {
    override val keySize: Int
        get() = params.l

    override val params: KyberParameterSpec

    override val y
        get() = secretKeyBytes

    var kyberKeySize: Kyber.KeySize? = null
        private set //Disable setting outside of class

    val secretKeyBytes: ByteArray
    val encodedSecretKeyBytes: ByteArray
        get() {
            val output = ByteArray(field.size)

            System.arraycopy(field, 0, output, 0, field.size) //Fresh array :D

            return output
        }

    val isGenerated
        get() = kyberKeySize != null


    constructor(keySize: Kyber.KeySize, secretKeyBytes: ByteArray) {
        this.params = KyberParameterSpec(Kyber.Params.DEFAULT_P, Kyber.Params.DEFAULT_G, keySize.length)
        this.kyberKeySize = keySize
        this.secretKeyBytes = ByteArray(secretKeyBytes.size)

        //Deep copy for Security Purposes
        System.arraycopy(secretKeyBytes, 0, this.secretKeyBytes, 0, secretKeyBytes.size)

        this.encodedSecretKeyBytes = generateEncodedBytes(this.secretKeyBytes)
    }

    constructor(encodedSecretKeyBytes: ByteArray) {
        val decodedSecretKeyBytes = decodeBytes(encodedSecretKeyBytes, 2)

        this.params = decodedSecretKeyBytes.first

        this.secretKeyBytes = decodedSecretKeyBytes.second
        this.encodedSecretKeyBytes = ByteArray(encodedSecretKeyBytes.size)

        //Deep copy for Security Purposes
        System.arraycopy(encodedSecretKeyBytes, 0, this.encodedSecretKeyBytes, 0, encodedSecretKeyBytes.size)
    }

    private fun generateEncodedBytes(keyBytes: ByteArray): ByteArray {
        val algorithmOutputStream = ByteArrayOutputStream()
        val algorithmSequenceGen = DERSequenceGenerator(algorithmOutputStream)

        algorithmSequenceGen.addObject(ASN1ObjectIdentifier(Kyber.OID_KYBER))

        val paramsOutputStream = ByteArrayOutputStream()
        val paramsSequenceGen = DERSequenceGenerator(paramsOutputStream)

        paramsSequenceGen.addObject(ASN1Integer(Kyber.Params.DEFAULT_P))
        paramsSequenceGen.addObject(ASN1Integer(Kyber.Params.DEFAULT_G))
        paramsSequenceGen.addObject(ASN1Integer(this.keySize.toLong()))

        paramsSequenceGen.close()

        algorithmSequenceGen.addObject(DERSequence.fromByteArray(paramsOutputStream.toByteArray()))

        algorithmSequenceGen.close()

        val outputStreamBuffer = ByteArrayOutputStream()
        val sequenceGenBuffer = DERSequenceGenerator(outputStreamBuffer)

        sequenceGenBuffer.addObject(DERSequence.fromByteArray(algorithmOutputStream.toByteArray()))
        sequenceGenBuffer.addObject(DERBitString(keyBytes))

        sequenceGenBuffer.close()

        return outputStreamBuffer.toByteArray()
    }

    private fun decodeBytes(encodedBytes: ByteArray, ignoreBytes: Int): Pair<KyberParameterSpec, ByteArray> {
        val copiedBytes = ByteArray(encodedBytes.size)

        //Deep copy since ByteArrayInputStream does not copy.
        System.arraycopy(encodedBytes, 0, copiedBytes, 0, encodedBytes.size)

        val derKeySequence = (DERSequence.fromByteArray(copiedBytes) as DERSequence).parser()

        val algorithmSequence = (derKeySequence.readObject() as DERSequence).parser()

        val oid = (algorithmSequence.readObject() as ASN1ObjectIdentifier).id ?: throw InvalidKeyException("Null OID")
        val paramsSequence = (algorithmSequence.readObject() as DERSequence).parser()

        val paramsP = (paramsSequence.readObject() as ASN1Integer).value
        val paramsG = (paramsSequence.readObject() as ASN1Integer).value
        var paramsL = -1

        val lTemp = paramsSequence.readObject()

        // Private-value length is OPTIONAL
        if (lTemp !is ASN1Null) {
            paramsL = (lTemp as ASN1Integer).intValueExact()
        }

        if (paramsSequence.readObject() !is ASN1Null) {
            throw InvalidKeyException("Extra parameter data")
        }

        val `in` = ASN1InputStream((derKeySequence.readObject() as DERBitString).bitStream)

        val rawArray: ByteArray = `in`.readAllBytes()
        val decodedBytes = ByteArray(rawArray.size - ignoreBytes)

        System.arraycopy(rawArray, ignoreBytes, decodedBytes, 0, rawArray.size - ignoreBytes)

        if(paramsL > 0 && paramsL != decodedBytes.size)
            throw KyberKeyDecodingException(paramsL, decodedBytes.size)

        paramsL = decodedBytes.size

        val kyberParameters = KyberParameterSpec(paramsP, paramsG, paramsL)

        if (derKeySequence.readObject() !is ASN1Null) {
            throw InvalidKeyException("Excess key data")
        }

        return Pair(kyberParameters, decodedBytes)
    }

    override fun getEncoded(): ByteArray {
        val returnArray = ByteArray(this.encodedSecretKeyBytes.size)

        //Deep copy
        System.arraycopy(this.encodedSecretKeyBytes, 0, returnArray, 0, this.encodedSecretKeyBytes.size)

        return returnArray
    }

    override fun getAlgorithm(): String {
        return "Kyber"
    }

    override fun getFormat(): String {
        return "X.509"
    }
}