import org.jetbrains.kotlin.daemon.common.toHexString
import org.jetbrains.kotlin.gradle.dsl.JvmTarget
import org.jetbrains.kotlin.gradle.plugin.mpp.pm20.util.libsDirectory
import java.io.FileInputStream
import java.nio.file.Files
import java.security.MessageDigest

plugins {
    kotlin("multiplatform") version "1.9.22" //Kotlin Multiplatform
    id("org.jetbrains.dokka") version "1.9.10"  //KDocs
    signing //GPG
}

group = "asia.hombre.kyber" //The value after the last '.' is considered the maven name i.e. asia.hombre:kyber:+
version = "0.4.5"

val projectName = project.group.toString().split(".").last() //Grab maven name
val baseProjectName = projectName.plus("-").plus(project.version)

val mavenDir = "./maven"
val mavenBundlingDir = "$mavenDir/bundling"
val mavenDeep = "$mavenBundlingDir/" + (project.group.toString().replace(".", "/")) + "/" + version

val jarFileName = baseProjectName.plus(".jar")
val pomFileName = baseProjectName.plus(".pom")
val javadocsFileName = baseProjectName.plus("-javadoc.jar")
val sourcesFileName = baseProjectName.plus("-sources.jar")
val mavenBundleFileName = baseProjectName.plus("-bundle.zip")

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

        tasks.register<Jar>("generateSourcesJar") {
            archiveFileName.set(sourcesFileName)
            from(sourceSets.commonMain.get().kotlin.asFileTree)
            from(sourceSets.jvmMain.get().kotlin.asFileTree)
        }

        //Separated as its own task
        tasks.register("cleanMaven") {
            //Clean mavenBundlingDir and keep the old generated bundles
            delete(file(mavenBundlingDir))
            //Create mavenDir upto the deepest dir
            Files.createDirectories(file(mavenDeep).toPath())
        }

        tasks.register<Zip>("bundleMaven") {
            dependsOn("cleanMaven", "generateSourcesJar", "jvmJar")

            doFirst {
                //Copy pom.xml and emptyjavadocs.zip then rename them
                copy {
                    from(".")
                    include("pom.xml", "emptyjavadocs.zip")
                    into(mavenDeep)
                    rename("pom.xml", pomFileName)
                    //Javadocs is required by Maven in order to publish. They allow "fake" or "empty" Javadocs.
                    rename("emptyjavadocs.zip", javadocsFileName)
                }
                //Copy jar build and sources
                copy {
                    from(libsDirectory.get())
                    include(jarFileName, sourcesFileName)
                    into(mavenDeep)
                }

                val files = fileTree(mavenBundlingDir)
                for(file in files) {
                    saveHash(file, sha1(file), ".sha1")
                    saveHash(file, md5(file), ".md5")
                    saveHash(file, sha256(file), ".sha256")
                    saveHash(file, sha512(file), ".sha512")
                }
                //Sign
                signing {
                    sign(file("$mavenDeep/$pomFileName"))
                    sign(file("$mavenDeep/$jarFileName"))
                    sign(file("$mavenDeep/$sourcesFileName"))
                    sign(file("$mavenDeep/$javadocsFileName"))
                }
            }
            //Grab everything from mavenBundlingDir
            from(mavenBundlingDir)
            //Include the deepest contents
            include("/*".repeat(project.group.toString().split(".").size + 2).removePrefix("/"))
            //Save to mavenDir
            destinationDirectory.set(file(mavenDir))
            //Set archive name
            archiveFileName.set(mavenBundleFileName)
        }

        val jvmJar by tasks.getting(org.gradle.jvm.tasks.Jar::class) {
            archiveFileName.set(jarFileName)

            doFirst {
                from(configurations.getByName("jvmRuntimeClasspath").map { if (it.isDirectory) it else zipTree(it) })
                //Uncomment to list jvm configurations
                /*println(configurations.names.toList().filter {
                    it.contains("jvm") &&!(it.contains("test") || it.contains("Test"))
                }.joinToString("\n"))*/
            }
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
                implementation("org.kotlincrypto:secure-random:0.2.0")
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
    val sha1 = MessageDigest.getInstance("SHA-1").digest(inStream.readBytes())
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
    val sha256 = MessageDigest.getInstance("SHA-256").digest(inStream.readBytes())
    inStream.close()
    return sha256.toHexString()
}

//Optional. Why not?
fun sha512(file: File): String {
    val inStream = FileInputStream(file)
    val sha512 = MessageDigest.getInstance("SHA-512").digest(inStream.readBytes())
    inStream.close()
    return sha512.toHexString()
}