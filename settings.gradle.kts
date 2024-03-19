pluginManagement {
    repositories {
        mavenCentral()
        gradlePluginPortal()
    }

    val kmm: String by settings
    val dokka: String by settings
    plugins {
        kotlin("multiplatform") version kmm
        id("org.jetbrains.dokka") version dokka
    }
}

plugins {
    id("org.gradle.toolchains.foojay-resolver-convention") version "0.8.0"
}

rootProject.name = "KyberKotlin"