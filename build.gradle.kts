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

import asia.hombre.neorust.option.LTOFlag
import asia.hombre.neorust.option.OptLevel
import asia.hombre.neorust.option.PanicFlag
import asia.hombre.neorust.task.CargoBuild
import org.jetbrains.dokka.gradle.engine.parameters.VisibilityModifier
import org.jetbrains.kotlin.gradle.dsl.JvmTarget
import org.jetbrains.kotlin.gradle.plugin.mpp.KotlinJvmCompilation
import org.jetbrains.kotlin.gradle.plugin.mpp.KotlinNativeTarget
import org.jetbrains.kotlin.gradle.targets.native.tasks.KotlinNativeSimulatorTest
import org.jetbrains.kotlin.gradle.targets.native.tasks.KotlinNativeTest
import org.jetbrains.kotlin.konan.target.HostManager
import java.io.ByteArrayOutputStream

val kmm: String = providers.gradleProperty("kmm").get()
val keccak: String = providers.gradleProperty("keccak").get()
val random: String = providers.gradleProperty("random").get()

plugins {
    kotlin("multiplatform") //Kotlin Multiplatform
    id("org.jetbrains.dokka")  //KDocs
    id("maven-publish")
    id("signing") //GPG
    id("asia.hombre.neorust") // Rust support
}

group = "asia.hombre"
version = "2.1.0"
description = "ML-KEM (NIST FIPS 203) for Kotlin Multiplatform with a Rust backend on native targets."

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

val rustTargetMap = mapOf(
    "linuxX64" to "x86_64-unknown-linux-gnu",
    "linuxArm64" to "aarch64-unknown-linux-gnu",
    "mingwX64" to "x86_64-pc-windows-gnu",
    "iosArm64" to "aarch64-apple-ios",
    "iosX64" to "x86_64-apple-ios",
    "iosSimulatorArm64" to "aarch64-apple-ios-sim",
    "androidNativeArm32" to "armv7-linux-androideabi",
    "androidNativeArm64" to "aarch64-linux-android",
    "androidNativeX64" to "x86_64-linux-android",
)

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
    linuxArm64()
    mingwX64()
    iosX64()
    iosArm64()
    iosSimulatorArm64()
    androidNativeArm32()
    androidNativeArm64()
    androidNativeX64()
    applyDefaultHierarchyTemplate()
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
                implementation("org.bouncycastle:bcprov-jdk15to18:1.86")
            }
        }
    }
}


tasks.withType<KotlinNativeTest>().configureEach {
    val projectDirectory = layout.projectDirectory.asFile.absolutePath
    environment("KYBER_TEST_PROJECT_DIR", projectDirectory, tracked = false)
    inputs.dir(layout.projectDirectory.dir("src/commonTest/resources"))
        .withPropertyName("commonTestFixtures")
        .withPathSensitivity(PathSensitivity.RELATIVE)
}

tasks.withType<KotlinNativeSimulatorTest>().configureEach {
    // xcrun simctl spawn does not preserve the host working directory and only forwards SIMCTL_CHILD_* variables.
    environment(
        "SIMCTL_CHILD_KYBER_TEST_PROJECT_DIR",
        layout.projectDirectory.asFile.absolutePath,
        tracked = false,
    )
}

rust {
    name = "kyberkotlin-ffi"
    authors.add("Ron Lauren Hombre <ronlauren@hombre.asia>")
    edition = "2024"
    publishEnabled = false
    locked = true
    offline = gradle.startParameter.isOffline

    dependencies {
        crate(project("kyberrust")) {
            defaultFeatures = false
            features.add("ffi")
        }
    }

    library {
        crateType.add("staticlib")
    }

    profiles {
        named("dev") {
            panic = PanicFlag.abort
        }

        named("release") {
            panic = PanicFlag.abort
            optLevel = OptLevel.three
            lto = LTOFlag.fat
            codegenUnits.set(1)
        }
    }

    kotlin.targets.withType<KotlinNativeTarget>().configureEach {
        val canBuildOnCurrentHost = HostManager().isEnabled(konanTarget)
        val goodName = name.replaceFirstChar { it.uppercase() }
        val rustTarget = rustTargetMap.getValue(name)
        val outputName = rust.name.get().lowercase().replace("-", "")
        val ffiTargetDirectory = rust.targetDirectory.dir(name)
        val ffiLibrary = ffiTargetDirectory.map { it.file("$rustTarget/release/lib$outputName.a") }
        val interopLibrary = layout.buildDirectory.file("ffi/$rustTarget/lib$outputName.a")
        val toolBaseDirectory = layout.projectDirectory.asFile
        val objcopyOptions = buildList {
            when {
                name == "mingwX64" -> {
                    // llvm-objcopy cannot weaken COFF symbols. Rename both the
                    // definition and its references to avoid Rust runtime collisions.
                    add("--redefine-sym=rust_eh_personality=kyberrust_eh_personality")
                }
                rustTarget.contains("apple") -> add("--weaken-symbol=_rust_eh_personality")
                else -> add("--weaken-symbol=rust_eh_personality")
            }
            if (name == "androidNativeArm32") {
                // The old NDK libgcc also supplies these atomic helpers.
                add("--wildcard")
                add("--weaken-symbol=__sync_*")
            }
            add("--strip-debug")
            add("--remove-section=.llvmbc")
            add("--remove-section=.llvmcmd")
        }

        val buildFFI = tasks.register<CargoBuild>("buildFFI$goodName") {
            description = "Build the KyberRust C ABI bridge for $rustTarget"
            group = "build ffi"
            dependsOn(":generateCargoManifest")
            onlyIf("Kotlin/Native supports C interop for this target on the current host") {
                canBuildOnCurrentHost
            }

            this.manifestPath = rust.manifestPath
            this.targetDirectory = ffiTargetDirectory

            // CargoBuild's generated manifest is outside the source tree.
            // Track both crates so edits cannot reuse an outdated static library.
            // This is a temporary fix while this is not tracked in NRGP.
            inputs.files(
                fileTree("src/library/rust") { include("**/*.rs") },
                fileTree("kyberrust/src/library/rust") { include("**/*.rs") },
                fileTree("keccakrust/src/library/rust") { include("**/*.rs") },
            ).withPropertyName("rustSources").withPathSensitivity(PathSensitivity.RELATIVE)

            target = rustTarget
            release = true
        }
        fun llvmTool(property: String, command: String): Provider<String> =
            providers.gradleProperty(property).orElse(command).map { path ->
                if (('/' in path || '\\' in path) && !File(path).isAbsolute) {
                    toolBaseDirectory.resolve(path).absolutePath
                } else path
            }

        val prepareFFI = tasks.register<PrepareFFI>("prepareFFI$goodName") {
            description = "Keep the Kyber FFI and its native dependencies for $rustTarget"
            group = "build ffi"
            dependsOn(buildFFI)
            onlyIf("Kotlin/Native supports C interop for this target on the current host") {
                canBuildOnCurrentHost
            }
            sourceArchive.set(ffiLibrary)
            preparedArchive.set(interopLibrary)
            llvmAr.set(llvmTool("kyber.llvmAr", "llvm-ar"))
            llvmNm.set(llvmTool("kyber.llvmNm", "llvm-nm"))
            llvmObjcopy.set(llvmTool("kyber.llvmObjcopy", "llvm-objcopy"))
            symbolOptions.set(objcopyOptions)

            pruneArchive.set(providers.gradleProperty("kyber.pruneArchive")
                .map { it.toBooleanStrict() }.orElse(true))
        }

        val rustInterop = compilations.getByName("main").cinterops.create("FFI") {
            definitionFile.set(layout.projectDirectory.file("ffi.def"))
            includeDirs(layout.projectDirectory.dir("src/library/rust/include").asFile)
            extraOpts("-libraryPath", interopLibrary.get().asFile.parentFile.absolutePath)
        }
        tasks.named(rustInterop.interopProcessingTaskName).configure {
            dependsOn(prepareFFI)
            inputs.file(interopLibrary)
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

fun parseArtifactArchiveName(artifactName: String, version: String): String {
    return "$artifactName-$version-bundle.zip"
}

val bundleAllTask = tasks.register("bundleAll") {
    description = "Bundles all the buildable Maven Artifacts"
    group = "Bundle"
    //dependsOn("publish")
}

val publishAllTask = tasks.register("publishAllToMavenCentral") {
    description = "Publishes and bundles all the buildable Maven Artifacts"
    group = "Publish"
    dependsOn("bundleAll")
}

gradle.projectsEvaluated {
    publishing.publications.withType<MavenPublication>().configureEach {
        artifactId = projectName + if (artifactId.contains("-")) "-" + artifactId.split("-").last() else ""
        val artifact = this
        val pubNameCap = artifact.name.replaceFirstChar { it.uppercase() }
        val bundleFileName = parseArtifactArchiveName(artifact.artifactId, artifact.version)
        val bundleTask = tasks.register<Zip>("bundle$pubNameCap") {
            description = "Bundles the Maven Artifact"
            group = "Bundle"
            from(mavenDir)
            val mavenDeepDir = artifact.groupId.replace(".", "/") + "/" + artifact.artifactId
            include("$mavenDeepDir/*/*")
            destinationDirectory.set(mavenDir)
            archiveFileName.set(bundleFileName)
        }

        val publishTask = tasks.register<Exec>("publish${pubNameCap}ToMavenCentral") {
            description = "Publish the Maven Artifact to Maven Central"
            mustRunAfter(bundleTask)
            group = "Publish"

            commandLine(
                "curl", "-X", "POST",
                "https://central.sonatype.com/api/v1/publisher/upload?name=${artifact.artifactId}&publishingType=" + if(isAutomated) "AUTOMATED" else "USER_MANAGED",
                "-H", "accept: text/plain",
                "-H", "Content-Type: multipart/form-data",
                "-H", "Authorization: Bearer " + System.getenv("SONATYPE_TOKEN"),
                "-F", "bundle=@$bundleFileName;type=application/x-zip-compressed"
            )
            workingDir(mavenDir)

            val stdOut = ByteArrayOutputStream()
            val errOut = ByteArrayOutputStream()
            standardOutput = stdOut
            errorOutput = errOut

            doLast {
                println(stdOut.toString())
                println(errOut.toString())
            }
        }

        // Attach dynamic tasks to root tasks
        bundleAllTask.configure { dependsOn(bundleTask) }
        publishAllTask.configure { dependsOn(publishTask) }
    }
}

dokka {
    pluginsConfiguration.html {
        footerMessage = "Copyright (c) 2026 Ron Lauren Hombre"
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

/**
 * Retain the FFI exports and their transitive native dependencies.
 *
 * This is important because of Maven Central's new publishing quota limits.
 */
@CacheableTask
abstract class PrepareFFI @Inject constructor(private val execOperations: ExecOperations) : DefaultTask() {
    @get:InputFile
    @get:PathSensitive(PathSensitivity.NONE)
    abstract val sourceArchive: RegularFileProperty

    @get:OutputFile
    abstract val preparedArchive: RegularFileProperty

    @get:Input
    abstract val llvmAr: Property<String>

    @get:Input
    abstract val llvmNm: Property<String>

    @get:Input
    abstract val llvmObjcopy: Property<String>

    @get:Input
    abstract val symbolOptions: ListProperty<String>

    @get:Input
    abstract val pruneArchive: Property<Boolean>

    private fun runTool(workDir: File, executable: String, arguments: List<String>): String {
        val stdout = ByteArrayOutputStream()
        execOperations.exec {
            workingDir(workDir)
            commandLine(buildList(arguments.size + 1) {
                add(executable)
                addAll(arguments)
            })
            standardOutput = stdout
        }.assertNormalExitValue()
        return stdout.toString(Charsets.UTF_8.name())
    }

    private fun keepFullArchive(reason: String) {
        logger.warn("$name: keeping the full FFI archive: $reason")
    }

    private fun prune(workDir: File, archiveName: String) {
        val members = ArrayList<String>()
        val uniqueMembers = HashSet<String>()
        for (line in runTool(workDir, llvmAr.get(), listOf("t", archiveName)).lineSequence()) {
            if (line.isNotEmpty()) {
                members.add(line)
                if (!uniqueMembers.add(line)) {
                    keepFullArchive("duplicate member names prevent unambiguous selection")
                    return
                }
            }
        }

        val prefix = "$archiveName["
        val definitions = HashMap<String, MutableSet<String>>()
        val undefinedByMember = HashMap<String, MutableSet<String>>()
        val commonMembers = HashSet<String>()

        val nmOutput = runTool(
            workDir,
            llvmNm.get(),
            listOf(
                "--format=posix",
                "--print-file-name",
                "--extern-only",
                "--no-demangle",
                "--no-sort",
                "--quiet",
                archiveName,
            ),
        )
        for (line in nmOutput.lineSequence()) {
            if (line.isBlank()) continue
            val separator = line.lastIndexOf("]: ")
            check(line.startsWith(prefix) && separator >= prefix.length) {
                "Unexpected llvm-nm output: $line"
            }
            val member = line.substring(prefix.length, separator)
            val rest = line.substring(separator + 3).trimStart()
            val nameEnd = rest.indexOfFirst { it.isWhitespace() }
            check(nameEnd > 0) { "Unexpected llvm-nm symbol: $line" }
            val symName = rest.substring(0, nameEnd)
            var kindIndex = nameEnd + 1
            while (kindIndex < rest.length && rest[kindIndex].isWhitespace()) kindIndex++
            check(kindIndex < rest.length && (kindIndex + 1 == rest.length || rest[kindIndex + 1].isWhitespace())) {
                "Unexpected llvm-nm symbol: $line"
            }

            when (val kind = rest[kindIndex]) {
                'U' -> undefinedByMember.getOrPut(member) { LinkedHashSet() }.add(symName)
                'w', 'v' -> Unit // Optional undefined weak symbols
                else -> {
                    if (kind == 'C') commonMembers.add(member)
                    definitions.getOrPut(symName) { LinkedHashSet() }.add(member)
                }
            }
        }

        val requiredExports = setOf(
            "kyberrust_generate", "kyberrust_generate_pke",
            "kyberrust_encapsulate", "kyberrust_decapsulate",
            "kyberrust_encrypt", "kyberrust_decrypt",
        )
        val foundExports = HashSet<String>()
        val selected = LinkedHashSet<String>()
        for ((symName, providers) in definitions) {
            val exportedName = symName.removePrefix("_")
            if (exportedName.startsWith("kyberrust_")) {
                foundExports.add(exportedName)
                if (providers.size > 1) {
                    keepFullArchive("an FFI export has multiple providers")
                    return
                }
                selected.addAll(providers)
            }
        }
        check(foundExports.containsAll(requiredExports)) {
            "The Rust archive is missing FFI exports: ${requiredExports - foundExports}"
        }

        val pending = ArrayDeque(selected)
        while (pending.isNotEmpty()) {
            val member = pending.removeFirst()
            if (member in commonMembers) {
                keepFullArchive("a selected member uses common-symbol resolution")
                return
            }
            for (symName in undefinedByMember[member].orEmpty()) {
                val providers = definitions[symName] ?: continue
                if (providers.any { it in selected }) continue
                if (providers.size > 1) {
                    keepFullArchive("$symName has multiple archive providers")
                    return
                }
                val provider = providers.first()
                if (selected.add(provider)) pending.addLast(provider)
            }
        }

        check(uniqueMembers.containsAll(selected)) { "llvm-nm reported an unknown archive member" }
        val removed = members.filterNot { it in selected }
        if (removed.isNotEmpty()) {
            // Delete from a copy: preserve member bytes, order and archive format.
            // A response file also avoids Windows command-line length limits.
            val response = workDir.resolve("remove.rsp")
            try {
                response.bufferedWriter().use { writer ->
                    for (member in removed) {
                        writer.write("\"")
                        writer.write(member.replace("\\", "\\\\").replace("\"", "\\\""))
                        writer.write("\"\n")
                    }
                }
                runTool(workDir, llvmAr.get(), listOf("--rsp-quoting=posix", "dsD", archiveName, "@${response.name}"))
            } finally {
                response.delete()
            }
        }
        logger.lifecycle("$name: retained ${selected.size}/${members.size} native archive members")
    }

    @TaskAction
    fun prepare() {
        val source = sourceArchive.get().asFile
        val output = preparedArchive.get().asFile
        val workDir = output.parentFile.apply { mkdirs() }
        val input = workDir.resolve("input.a")
        source.copyTo(input, overwrite = true)
        try {
            if (pruneArchive.get()) {
                prune(workDir, input.name)
            }
            runTool(workDir, llvmObjcopy.get(), symbolOptions.get() + listOf(input.name, output.name))
        } finally {
            input.delete()
        }
        logger.lifecycle("$name: ${source.length()} -> ${output.length()} bytes")
    }
}
