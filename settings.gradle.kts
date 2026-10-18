/*
 * Copyright 2026 Ron Lauren Hombre
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *        
 *        and included as LICENSE.txt in this Project.
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

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