plugins {
    kotlin("jvm") version "1.9.20"
}

group = "asia.hombre.kyber"
version = "0.0.1"

repositories {
    mavenCentral()
}

dependencies {
    implementation("org.bouncycastle:bcutil-jdk18on:1.77")
    implementation("org.kotlincrypto.hash:sha3:0.4.0")

    testImplementation(kotlin("test"))
}

tasks.test {
    useJUnitPlatform()
}

kotlin {
    jvmToolchain(17)
}