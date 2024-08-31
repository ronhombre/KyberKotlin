const { KyberParameter, KyberKeyGenerator } = require("./kotlin/KyberKotlin").asia.hombre.kyber;

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