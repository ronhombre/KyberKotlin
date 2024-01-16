import org.jetbrains.kotlin.daemon.common.toHexString
import org.jetbrains.kotlin.gradle.dsl.JvmTarget
import java.io.FileInputStream
import java.nio.file.Files
import java.security.MessageDigest

plugins {
    kotlin("multiplatform") version "1.9.21"
    id("org.jetbrains.dokka") version "1.9.10"
    signing
}

group = "asia.hombre.kyber"
version = "0.2.6"

val projectName = project.group.toString().split(".").last()
val baseProjectName = projectName.plus("-").plus(project.version)
val mavenDir = "./maven"
val mavenDeep = "$mavenDir/" + (project.group.toString().replace(".", "/")) + "/" + version

repositories {
    mavenCentral()
}

kotlin {
    jvm {
        val main by compilations.getting {
            compilerOptions.configure {
                // Set up the Kotlin compiler options for the 'main' compilation:
                jvmTarget.set(JvmTarget.JVM_1_8)
            }

            compileTaskProvider // get the Kotlin task 'compileKotlinJvm'
            output // get the main compilation output
        }

        val generateSourcesJar = tasks.create<Jar>("generateSourcesJar") {
            archiveFileName.set("$baseProjectName-sources.jar")
            from(sourceSets.commonMain.get().kotlin.asFileTree)
            from(sourceSets.jvmMain.get().kotlin.asFileTree)
        }

        val bundleMaven = tasks.create<Zip>("bundleMaven") {
            doFirst {
                val files = fileTree(mavenDir)
                for(file in files) {
                    if(file.name.endsWith(".asc")) continue //Ignore GPG Signature File
                    saveHash(file, sha1(file), ".sha1")
                    saveHash(file, md5(file), ".md5")
                    saveHash(file, sha256(file), ".sha256")
                    saveHash(file, sha512(file), ".sha512")
                }
            }
            from(mavenDir)
            include("/*".repeat(project.group.toString().split(".").size + 2).removePrefix("/"))
            exclude("*.zip")
            destinationDirectory.set(file(mavenDir))
            archiveFileName.set("$baseProjectName-bundle.zip")
        }

        val jvmJar by tasks.getting(org.gradle.jvm.tasks.Jar::class) {
            archiveFileName.set(baseProjectName.plus(".jar"))
            doFirst {
                from(configurations.getByName("jvmRuntimeClasspath").map { if (it.isDirectory) it else zipTree(it) })
                //Clean mavenDir
                delete(file(mavenDir))
            }
            doLast {
                //Create mavenDir
                Files.createDirectories(file(mavenDeep).toPath())
                //Copy pom.xml
                copy {
                    from(".")
                    include("pom.xml", "emptyjavadocs.zip")
                    into(mavenDeep)
                    rename("pom.xml", baseProjectName.plus(".pom"))
                    rename("emptyjavadocs.zip", "$baseProjectName-javadoc.jar")
                }
                //Copy jar build
                copy {
                    from(destinationDirectory)
                    include(archiveFileName.get(), "$baseProjectName-sources.jar")
                    into(mavenDeep)
                }
                //Sign
                signing {
                    sign(file("$mavenDeep/" + baseProjectName.plus(".pom")))
                    sign(file("$mavenDeep/" + archiveFileName.get()))
                    sign(file("$mavenDeep/$baseProjectName-sources.jar"))
                    sign(file("$mavenDeep/$baseProjectName-javadoc.jar"))
                }
            }
            dependsOn("generateSourcesJar")
            finalizedBy("bundleMaven")
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
        val jsMain by getting {
            dependencies {

            }
        }
    }
}

fun saveHash(file: File, hash: String, suffix: String) {
    val filePath = file.toPath()
    Files.write(filePath.resolveSibling(filePath.fileName.toString() + suffix), hash.toByteArray())
}

//Required for Maven
fun sha1(file: File): String {
    val inStream = FileInputStream(file)
    val sha1 = MessageDigest.getInstance("SHA1").digest(inStream.readBytes())
    inStream.close()
    return sha1.toHexString()
}

//Required for Maven
fun md5(file: File): String {
    val inStream = FileInputStream(file)
    val md5 = MessageDigest.getInstance("MD5").digest(inStream.readBytes())
    inStream.close()
    return md5.toHexString()
}

//Optional. Why not?
fun sha256(file: File): String {
    val inStream = FileInputStream(file)
    val sha1 = MessageDigest.getInstance("SHA256").digest(inStream.readBytes())
    inStream.close()
    return sha1.toHexString()
}

//Optional. Why not?
fun sha512(file: File): String {
    val inStream = FileInputStream(file)
    val sha1 = MessageDigest.getInstance("SHA512").digest(inStream.readBytes())
    inStream.close()
    return sha1.toHexString()
}