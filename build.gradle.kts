import org.jetbrains.dokka.gradle.engine.parameters.VisibilityModifier
import org.jetbrains.kotlin.gradle.dsl.JvmTarget
import org.jetbrains.kotlin.gradle.plugin.mpp.KotlinJvmCompilation
import java.io.ByteArrayOutputStream
import java.nio.file.Files

val kmm: String = providers.gradleProperty("kmm").get()
val keccak: String = providers.gradleProperty("keccak").get()
val random: String = providers.gradleProperty("random").get()

plugins {
    kotlin("multiplatform") //Kotlin Multiplatform
    id("org.jetbrains.dokka")  //KDocs
    id("maven-publish")
    id("signing") //GPG
}

group = "asia.hombre"
version = "2.0.1"
description = "ML-KEM (NIST FIPS 203) optimized implementation on 100% Kotlin."

val projectName = "kyber"
val baseProjectName = projectName.plus("-").plus(project.version)

val isAutomated = false

val mavenDir = projectDir.resolve("maven")
val mavenBundlingDir = mavenDir.resolve("bundling")
val mavenDeep = "$mavenBundlingDir/" + (project.group.toString().replace(".", "/")) + "/" + version

val npmDir = "./npm"
val npmKotlinDir = "$npmDir/kotlin"

val jarFileName = baseProjectName.plus(".jar")
val jarFullFileName = baseProjectName.plus("-full.jar")
val javadocsFileName = baseProjectName.plus("-javadoc.jar")
val sourcesFileName = baseProjectName.plus("-sources.jar")
val mavenBundleFileName = baseProjectName.plus("-bundle.zip")

repositories {
    mavenCentral()
    mavenLocal()
}

kotlin {
    jvm {
        @Suppress("unused")
        compilations.getByName("main") {
            compileTaskProvider.configure {
                //Set up the Kotlin compiler options for the 'main' compilation:
                compilerOptions.jvmTarget.set(JvmTarget.JVM_1_8)
            }

            compileTaskProvider //Get the Kotlin task 'compileKotlinJvm'
            output //Get the main compilation output
        }

        @Suppress("unused")
        tasks.getByName("jvmJar", org.gradle.jvm.tasks.Jar::class) {
            archiveFileName.set(jarFileName)

            val jvmMainCompilation = kotlin.targets.getByName("jvm").compilations.getByName("main") as KotlinJvmCompilation

            from(jvmMainCompilation.output.allOutputs)
        }

        compilations["test"].runtimeDependencyFiles // get the test runtime classpath
    }
    linuxX64()
    //linuxArm64()
    mingwX64()
    //iosArm64()
    //iosX64()
    //iosSimulatorArm64()
    androidNativeArm32()
    androidNativeArm64()
    androidNativeX64()
    sourceSets {
        @Suppress("unused")
        getByName("commonMain") {
            dependencies {
                implementation("org.kotlincrypto.random:crypto-rand:$random")
                implementation("asia.hombre:keccak:$keccak")
            }
        }
        @Suppress("unused")
        getByName("commonTest") {
            dependencies {
                implementation("org.jetbrains.kotlin:kotlin-test")
            }
        }
        @Suppress("unused")
        getByName("jvmTest") {
            dependencies {
                implementation("org.bouncycastle:bcprov-jdk15to18:1.85.2")
            }
        }
    }
}

signing {
    if (project.hasProperty("signing.gnupg.keyName")) {
        useGpgCmd()
        sign(publishing.publications)
    }
}

publishing {
    repositories {
        maven {
            url = mavenDir.toURI()
        }
    }
    publications {
        //Dynamically rename all artifacts
        this.forEach {
            val mavenPublication = it as MavenPublication
            mavenPublication.artifactId = projectName +
                    if(mavenPublication.artifactId.contains("-"))
                        "-" + mavenPublication.artifactId.split("-").last()
                    else
                        ""
        }
    }
    publications.withType<MavenPublication> {
        // Stub javadoc.jar artifact
        artifact(tasks.register("${name}JavadocJar", Jar::class) {
            archiveClassifier.set("javadoc")
            archiveAppendix.set(this@withType.name)
        })

        // Provide artifacts information required by Maven Central
        pom {
            name.set("Kyber Kotlin Multiplatform Library")
            description.set(project.description)
            url.set("https://github.com/ronhombre/KyberKotlin")

            licenses {
                license {
                    name.set("The Apache Software License, Version 2.0")
                    url.set("https://www.apache.org/licenses/LICENSE-2.0.txt")
                }
            }
            developers {
                developer {
                    name.set("Ron Lauren Hombre")
                    email.set("ronlauren@hombre.asia")
                }
            }
            scm {
                url.set("https://github.com/ronhombre/KyberKotlin")
            }
        }
    }
}

fun parseArtifactId(artifactId: String): String {
    val list = artifactId.splitToSequence("-").map { it.replaceFirstChar(Char::uppercase) }

    return list.joinToString("")
}

fun parseArtifactArchiveName(artifact: MavenPublication): String {
    return artifact.artifactId + "-" + artifact.version + "-bundle.zip"
}

for ((_, value) in publishing.publications.asMap) {
    val artifact = value as MavenPublication
    val parsedArtifactId = parseArtifactId(artifact.artifactId)
    val bundleFileName = parseArtifactArchiveName(artifact)

    tasks.register<Zip>("bundle$parsedArtifactId") {
        description = "Bundles the Maven Artifact"
        group = "Bundle"
        from(mavenDir)
        val mavenDeepDir = artifact.groupId.replace(".", "/") + "/" + artifact.artifactId
        include("$mavenDeepDir/*/*")
        destinationDirectory = mavenDir
        archiveFileName = parseArtifactArchiveName(artifact)
    }

    tasks.register<Exec>("publish" + parsedArtifactId + "ToMavenCentral") {
        description = "Publishes and bundles the Maven Artifact to Maven Central"
        mustRunAfter("bundle$parsedArtifactId")
        group = "Publish"
        /*if(!mavenDir.resolve(bundleFileName).exists())
            throw RuntimeException("Bundle does not exist! Please run `bundle$parsedArtifactId`")*/

        commandLine(
            "curl", "-X", "POST",
            "https://central.sonatype.com/api/v1/publisher/upload?name=${artifact.artifactId}&publishingType=" + if(isAutomated) "AUTOMATED" else "USER_MANAGED",
            "-H", "accept: text/plain",
            "-H", "Content-Type: multipart/form-data",
            "-H", "Authorization: Bearer " + System.getenv("SONATYPE_TOKEN"),
            "-F", "bundle=@$bundleFileName;type=application/x-zip-compressed"
        )
        workingDir(mavenDir.toString())
        standardOutput = ByteArrayOutputStream()
        errorOutput = ByteArrayOutputStream()

        // Execute some action with the output
        doLast {
            println("$standardOutput")
            println("$errorOutput")
        }
    }
}

tasks.register("bundleAll") {
    description = "Bundles all the buildable Maven Artifacts"
    group = "Bundle"
    dependsOn("publish")

    for (publication in publishing.publications.asMap) {
        val artifact = publication.value as MavenPublication

        dependsOn("bundle" + parseArtifactId(artifact.artifactId))
    }
}

tasks.register("publishAllToMavenCentral") {
    description = "Publishes and bundles all the buildable Maven Artifacts"
    group = "Publish"
    dependsOn("bundleAll")

    for (publication in publishing.publications.asMap) {
        val artifact = publication.value as MavenPublication

        dependsOn("publish" + parseArtifactId(artifact.artifactId) + "ToMavenCentral")
    }
}

dokka {
    pluginsConfiguration.html {
        footerMessage = "Copyright (c) 2025 Ron Lauren Hombre"
    }

    dokkaPublications.html {
        dokkaSourceSets {
            named("commonMain") {
                perPackageOption {
                    matchingRegex.set(".*")
                }
                reportUndocumented.set(true)
                documentedVisibilities(
                    VisibilityModifier.Public,
                    VisibilityModifier.Protected,
                )
            }
        }
    }
}