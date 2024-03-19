import org.jetbrains.dokka.gradle.DokkaTask
import org.jetbrains.kotlin.daemon.common.toHexString
import org.jetbrains.kotlin.gradle.dsl.JvmTarget
import org.jetbrains.kotlin.gradle.plugin.mpp.KotlinJvmCompilation
import org.jetbrains.kotlin.gradle.plugin.mpp.pm20.util.libsDirectory
import java.io.FileInputStream
import java.nio.file.Files
import java.security.MessageDigest
import kotlin.io.path.Path

val kmm: String by properties
val hash: String by properties
val keccak: String by properties
val endians: String by properties
val random: String by properties

plugins {
    kotlin("multiplatform") //Kotlin Multiplatform
    id("org.jetbrains.dokka")  //KDocs
    signing //GPG
}

group = "asia.hombre.kyber" //The value after the last '.' is considered the maven name i.e. asia.hombre:kyber:+
version = "0.5.0"
description = "ML-KEM (NIST FIPS 203) optimized implementation on 100% Kotlin."

val projectName = project.group.toString().split(".").last() //Grab maven name
val baseProjectName = projectName.plus("-").plus(project.version)

val mavenDir = "./maven"
val mavenBundlingDir = "$mavenDir/bundling"
val mavenDeep = "$mavenBundlingDir/" + (project.group.toString().replace(".", "/")) + "/" + version

val npmDir = "./npm"
val npmKotlinDir = "$npmDir/kotlin"

val jarFileName = baseProjectName.plus(".jar")
val jarFullFileName = baseProjectName.plus("-full.jar")
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
                //Set up the Kotlin compiler options for the 'main' compilation:
                jvmTarget.set(JvmTarget.JVM_1_8)
            }

            compileTaskProvider //Get the Kotlin task 'compileKotlinJvm'
            output //Get the main compilation output
        }

        tasks.register<Jar>("generateSourcesJar") {
            archiveFileName.set(sourcesFileName)
            from(sourceSets.commonMain.get().kotlin.asFileTree)
            from(sourceSets.jvmMain.get().kotlin.asFileTree)
        }

        tasks.register<Jar>("generateDocsJar") {
            dependsOn("dokkaHtml")
            archiveFileName.set(javadocsFileName)
            from(files(buildDir.toPath().resolve("dokka").resolve("html")).asFileTree)
        }

        //Separated as its own task
        tasks.register("cleanMaven") {
            //Clean mavenBundlingDir and keep the old generated bundles
            delete(file(mavenBundlingDir))
            //Create mavenDir upto the deepest dir
            Files.createDirectories(file(mavenDeep).toPath())
        }

        tasks.register<Zip>("bundleMaven") {
            dependsOn("cleanMaven", "generateSourcesJar", "jvmJar", "generateDocsJar")

            doFirst {
                //Copy pom.xml, put the versions, and the description into it.
                val pomSourcePath = projectDir.toPath().resolve("pom.xml")
                val pomPath = Path(projectDir.path + mavenDeep.removePrefix(".")).resolve(pomFileName)

                var packageFile = String(Files.readAllBytes(pomSourcePath))
                packageFile = packageFile
                    .replace("0<!--VERSION-->", version.toString())
                    .replace("<!--DESCRIPTION-->", project.description.toString())
                    .replace("<!--KMM-->", kmm)
                    .replace("<!--HASH-->", hash)
                    .replace("<!--KECCAK-->", keccak)
                    .replace("<!--ENDIANS-->", endians)
                    .replace("<!--RANDOM-->", random)
                Files.write(pomPath, packageFile.toByteArray())

                //Copy jar build and sources
                copy {
                    from(libsDirectory.get())
                    include(jarFileName, sourcesFileName, javadocsFileName)
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
                    useGpgCmd()
                    //Specify which key to use
                    sign(configurations.getByName(runtimeElementsConfigurationName))
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

            val jvmMainCompilation = kotlin.targets.getByName("jvm").compilations.getByName("main") as KotlinJvmCompilation

            from(jvmMainCompilation.output.allOutputs)
        }

        tasks.register<Jar>("jvmFullJar") {
            archiveFileName.set(jarFullFileName)

            val jvmMainCompilation = kotlin.targets.getByName("jvm").compilations.getByName("main") as KotlinJvmCompilation

            // Include runtime dependencies by expanding them into the JAR
            from(configurations.getByName("jvmRuntimeClasspath").map { if (it.isDirectory) it else zipTree(it) },
                jvmMainCompilation.output.allOutputs)

            // Set a duplicate strategy (optional)
            duplicatesStrategy = DuplicatesStrategy.EXCLUDE
        }

        compilations["test"].runtimeDependencyFiles // get the test runtime classpath
    }
    js(IR) {
        nodejs()
        browser {

        }
        binaries.executable()

        tasks.register("packageNPM") {
            val packageSourcePath = projectDir.toPath().resolve("npm.json")
            val packagePath = projectDir.toPath().resolve("npm").resolve("package.json")

            var packageFile = String(Files.readAllBytes(packageSourcePath))
            packageFile = packageFile.replace("<VERSION>", version.toString()).replace("<DESCRIPTION>", project.description.toString())
            Files.write(packagePath, packageFile.toByteArray())
        }

        tasks.register<Copy>("bundleNPM") {
            dependsOn("jsBrowserProductionWebpack", "packageNPM")

            from(buildDir.resolve("js").resolve("packages").resolve(project.name).resolve("kotlin"))
            into(npmKotlinDir)

            doFirst {
                delete(npmKotlinDir)
                mkdir(npmKotlinDir)
            }
        }
    }
    mingwX64("windows") {
        binaries {
            sharedLib {  }
        }
    }
    sourceSets {
        val commonMain by getting {
            dependencies {
                implementation("org.kotlincrypto.hash:sha3:$hash")
                implementation("org.kotlincrypto.sponges:keccak:$keccak")
                implementation("org.kotlincrypto.endians:endians:$endians")
                implementation("org.kotlincrypto:secure-random:$random")
            }
        }
        val commonTest by getting {
            dependencies {
                implementation("org.jetbrains.kotlin:kotlin-test")
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

tasks.dokkaHtml.configure {
    dokkaSourceSets {
        named("commonMain") {
            // Adjust visibility to include internal and private members
            perPackageOption {
                matchingRegex.set(".*") // Match all packages
                includeNonPublic.set(false)
            }
            // Optionally, report undocumented members
            reportUndocumented.set(true)
        }
    }
}
tasks.withType<DokkaTask>().configureEach {
    val dokkaBaseConfiguration = """
    {
      "footerMessage": "(C) 2024 Ron Lauren Hombre"
    }
    """
    pluginsMapConfiguration.set(
        mapOf(
            // fully qualified plugin name to json configuration
            "org.jetbrains.dokka.base.DokkaBase" to dokkaBaseConfiguration
        )
    )
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