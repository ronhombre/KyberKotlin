pluginManagement {
    repositories {
        mavenCentral()
        gradlePluginPortal()
    }

    val kmm: String = providers.gradleProperty("kmm").get()
    val dokka: String = providers.gradleProperty("dokka").get()
    val nrgp: String = providers.gradleProperty("nrgp").get()
    plugins {
        kotlin("multiplatform") version kmm
        id("org.jetbrains.dokka") version dokka
        id("asia.hombre.neorust") version nrgp
    }
}

plugins {
    id("org.gradle.toolchains.foojay-resolver-convention") version "0.8.0"
}

rootProject.name = "KyberKotlin"
include("keccakrust")
include("kyberrust")