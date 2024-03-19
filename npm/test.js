const { KyberParameter, KyberKeyGenerator, KyberAgreement } = require("./kotlin/KyberKotlin").asia.hombre.kyber;

let aliceKeypair = KyberKeyGenerator.Companion.generate(KyberParameter.ML_KEM_512);
let bobKeypair = KyberKeyGenerator.Companion.generate(KyberParameter.ML_KEM_512);

let aliceAgreement = new KyberAgreement(aliceKeypair);
let bobAgreement = new KyberAgreement(bobKeypair);

let results = bobAgreement.encapsulate(aliceKeypair.encapsulationKey);

let ciphertext = results.cipherText;
let bobSecretKey = results.secretKey;

let aliceSecretKey = aliceAgreement.decapsulate(ciphertext);

console.assert(contentEquals(aliceSecretKey, bobSecretKey), "Secret Keys does not match!");

//Simple check
function contentEquals(a, b) {
    for(let i = 0; i < a.length; i++)
        if(a[i] !== b[i])
            return false;
    return true;
}