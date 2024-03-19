const { KyberParameter, KyberKeyGenerator, KyberAgreement } = require("./kotlin/KyberKotlin").asia.hombre.kyber;

function test512() {
    console.log("Testing 512...");
    let aliceKeypair = KyberKeyGenerator.Companion.generate(KyberParameter.ML_KEM_512);
    let bobKeypair = KyberKeyGenerator.Companion.generate(KyberParameter.ML_KEM_512);

    let aliceAgreement = new KyberAgreement(aliceKeypair);
    let bobAgreement = new KyberAgreement(bobKeypair);

    let results = bobAgreement.encapsulate(aliceKeypair.encapsulationKey);

    let ciphertext = results.cipherText;
    let bobSecretKey = results.secretKey;

    let aliceSecretKey = aliceAgreement.decapsulate(ciphertext);

    console.assert(contentEquals(aliceSecretKey, bobSecretKey), "Secret Keys for 512 does not match!");
}

function test768() {
    console.log("Testing 768...");
    let aliceKeypair = KyberKeyGenerator.Companion.generate(KyberParameter.ML_KEM_768);
    let bobKeypair = KyberKeyGenerator.Companion.generate(KyberParameter.ML_KEM_768);

    let aliceAgreement = new KyberAgreement(aliceKeypair);
    let bobAgreement = new KyberAgreement(bobKeypair);

    let results = bobAgreement.encapsulate(aliceKeypair.encapsulationKey);

    let ciphertext = results.cipherText;
    let bobSecretKey = results.secretKey;

    let aliceSecretKey = aliceAgreement.decapsulate(ciphertext);

    console.assert(contentEquals(aliceSecretKey, bobSecretKey), "Secret Keys for 768 does not match!");
}

function test1024() {
    console.log("Testing 1024...");
    let aliceKeypair = KyberKeyGenerator.Companion.generate(KyberParameter.ML_KEM_1024);
    let bobKeypair = KyberKeyGenerator.Companion.generate(KyberParameter.ML_KEM_1024);

    let aliceAgreement = new KyberAgreement(aliceKeypair);
    let bobAgreement = new KyberAgreement(bobKeypair);

    let results = bobAgreement.encapsulate(aliceKeypair.encapsulationKey);

    let ciphertext = results.cipherText;
    let bobSecretKey = results.secretKey;

    let aliceSecretKey = aliceAgreement.decapsulate(ciphertext);

    console.assert(contentEquals(aliceSecretKey, bobSecretKey), "Secret Keys for 1024 does not match!");
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