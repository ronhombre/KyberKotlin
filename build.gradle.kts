import org.jetbrains.kotlin.gradle.dsl.JvmTarget

plugins {
    kotlin("multiplatform") version "1.9.21"
}

group = "asia.hombre.kyber"
version = "0.2.1"

repositories {
    mavenCentral()
}

kotlin {
    jvm {
        val main by compilations.getting {
            compilerOptions.configure {
                // Set up the Kotlin compiler options for the 'main' compilation:
                jvmTarget.set(JvmTarget.JVM_17)
            }

            compileTaskProvider // get the Kotlin task 'compileKotlinJvm'
            output // get the main compilation output
        }

        compilations["test"].runtimeDependencyFiles // get the test runtime classpath
    }
    js().nodejs()
    sourceSets {
        val commonMain by getting {
            dependencies {
                implementation("org.kotlincrypto.hash:sha3:0.4.0")
                implementation("org.kotlincrypto.sponges:keccak:0.2.0")
                implementation("org.kotlincrypto.endians:endians:0.2.0")
            }
        }
        val commonTest by getting {
            dependencies {
                implementation("org.jetbrains.kotlin:kotlin-test") // This brings all the platform dependencies automatically
            }
        }
        val jvmMain by getting {
            dependencies {

            }
        }
    }
}