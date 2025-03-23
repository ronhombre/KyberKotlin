const { KyberKeyGenerator, KyberParameter, KyberEncapsulationKey, KyberCipherText } = require("./kotlin/KyberKotlin").asia.hombre.kyber;

function sample() {
    //Alice generates an ML-KEM Keypair containing a Decapsulation(Private) Key and an Encapsulation(Public) Key
    let keyPairAlice = KyberKeyGenerator.generate(KyberParameter.ML_KEM_512)

    //Alice sends the Encapsulation Key to Bob
    let keyBytesToBob = keyPairAlice.encapsulationKey.fullBytes //You can convert this to any format

    //Bob creates an instance of the Encapsulation Key from the bytes Alice sent
    let aliceEncapsKey = KyberEncapsulationKey.Companion.fromBytes(keyBytesToBob)

    //Bob runs the encapsulation algorithm. Here, this is just a method you call
    let encapsResult = aliceEncapsKey.encapsulate()
    //The result contains both the Cipher Text and the Shared Secret Key

    //Bob returns the Cipher Text to Alice
    let cipherTextBytesToAlice = encapsResult.cipherText.fullBytes //You can convert this to any format

    //Alice creates an instance of a Cipher Text from the bytes Bob responds with
    let bobCipherText = KyberCipherText.Companion.fromBytes(cipherTextBytesToAlice)

    //Alice runs the decapsulation algorithm. Here, this is just a method you call
    let decapsResult = keyPairAlice.decapsulationKey.decapsulate(bobCipherText)
    //The returned value is the Shared Secret Key

    //Alice generated the Secret Key
    console.log(encapsResult.sharedSecretKey)
    //Bob decapsulated the same Secret Key
    console.log(decapsResult)

    console.log(contentEquals(encapsResult.sharedSecretKey, decapsResult))

    /* IMPORTANT NOTE:
        In this library, Bob DOES NOT need to generate an ML-KEM Key Pair. Bob only needs to ENCAPSULATE and RETURN the
    Cipher Text to Alice.

        THE RESULT OF THIS LIBRARY MUST WORK WITH ALL ML-KEM SPECIFIED LIBRARIES. THUS, IT DOES NOT MATTER IF THE BOB
    IN YOUR ARCHITECTURE OR SYSTEM USES KyberKotlin.
     */
}

sample()

function test512() {
    console.log("Testing 512...");
    let aliceKeypair = KyberKeyGenerator.generate(KyberParameter.ML_KEM_512);

    let results = aliceKeypair.encapsulationKey.encapsulate();

    let ciphertext = results.cipherText;
    let bobSecretKey = results.sharedSecretKey;

    let aliceSecretKey = aliceKeypair.decapsulationKey.decapsulate(ciphertext);

    console.assert(contentEquals(aliceSecretKey, bobSecretKey), "Shared Secret Keys for 512 does not match!");
}

function test768() {
    console.log("Testing 768...");
    let aliceKeypair = KyberKeyGenerator.generate(KyberParameter.ML_KEM_768);

    let results = aliceKeypair.encapsulationKey.encapsulate();

    let ciphertext = results.cipherText;
    let bobSecretKey = results.sharedSecretKey;

    let aliceSecretKey = aliceKeypair.decapsulationKey.decapsulate(ciphertext);

    console.assert(contentEquals(aliceSecretKey, bobSecretKey), "Shared Secret Keys for 768 does not match!");
}

function test1024() {
    console.log("Testing 1024...");
    let aliceKeypair = KyberKeyGenerator.generate(KyberParameter.ML_KEM_1024);

    let results = aliceKeypair.encapsulationKey.encapsulate();

    let ciphertext = results.cipherText;
    let bobSecretKey = results.sharedSecretKey;

    let aliceSecretKey = aliceKeypair.decapsulationKey.decapsulate(ciphertext);

    console.assert(contentEquals(aliceSecretKey, bobSecretKey), "Shared Secret Keys for 1024 does not match!");
}

test512();
test768();
test1024();

console.log("Success.")

//Simple check
function contentEquals(a, b) {
    for(let i = 0; i < a.length; i++)
        if(a[i] !== b[i])
            return false;
    return true;
}