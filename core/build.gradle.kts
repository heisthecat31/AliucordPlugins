import org.jetbrains.kotlin.gradle.dsl.JvmTarget

// Pure-JVM half of DaveVoice: DAVE/MLS session handling, frame + transport crypto and the UDP relay.
// Kept free of Android and Discord classes so it can be unit tested (and driven by a desktop harness) on a PC.
plugins {
    alias(libs.plugins.kotlin.jvm)
}

java {
    // The plugin dex is built with minSdk 21, so stay on Java 8 bytecode and APIs.
    sourceCompatibility = JavaVersion.VERSION_1_8
    targetCompatibility = JavaVersion.VERSION_1_8
}

kotlin {
    compilerOptions {
        jvmTarget = JvmTarget.JVM_1_8
    }
}

dependencies {
    // Discord 126.21 ships kotlin-stdlib 1.5.21 and plugins run against it, so compile and test against the same.
    compileOnly(libs.kotlin.stdlib)
    implementation(libs.bcmls)

    testImplementation(libs.kotlin.stdlib)
    testImplementation(libs.junit)
}

// Shrink the core + BouncyCastle (~10 MB of jars) down to what is actually used, so the plugin dex stays small and
// under the 64K method limit. Names are kept: on API 21+ Android's own BouncyCastle lives in com.android.org.*.
val sdkDir: String = rootProject.file("local.properties").takeIf { it.exists() }
    ?.readLines()?.firstOrNull { it.startsWith("sdk.dir=") }?.substringAfter("=")?.replace("\\:", ":")
    ?: System.getenv("ANDROID_HOME")
    ?: error("Set sdk.dir in local.properties or ANDROID_HOME")

val shrinkJar by tasks.registering(JavaExec::class) {
    val coreJar = tasks.jar.flatMap { it.archiveFile }
    val runtime = configurations.runtimeClasspath.get()
    val stdlib = configurations.compileClasspath.get().filter { it.name.startsWith("kotlin-stdlib") }
    val rules = file("r8-rules.pro")
    val output = layout.buildDirectory.file("libs/core-shrunk.jar")
    val androidJar = file("$sdkDir/platforms").listFiles { f -> f.resolve("android.jar").exists() }
        ?.maxByOrNull { it.name.removePrefix("android-").toIntOrNull() ?: 0 }?.resolve("android.jar")
        ?: error("No Android platform with android.jar found in $sdkDir")

    inputs.file(coreJar)
    inputs.files(runtime, stdlib, rules)
    outputs.file(output)

    // R8 ships inside build-tools' d8.jar; use the newest installed build-tools.
    val buildTools = file("$sdkDir/build-tools").listFiles { f -> f.resolve("lib/d8.jar").exists() }
        ?.maxByOrNull { dir -> dir.name.split('.', '-').map { it.toIntOrNull() ?: 0 }.fold(0L) { acc, n -> acc * 1000 + n } }
        ?: error("No Android build-tools with lib/d8.jar found in $sdkDir")
    classpath = files(buildTools.resolve("lib/d8.jar"))
    mainClass.set("com.android.tools.r8.R8")
    argumentProviders.add(
        CommandLineArgumentProvider {
            listOf(
                "--classfile",
                "--output", output.get().asFile.absolutePath,
                "--pg-conf", rules.absolutePath,
                "--lib", androidJar.absolutePath,
            ) + stdlib.files.flatMap { listOf("--classpath", it.absolutePath) } +
                coreJar.get().asFile.absolutePath + runtime.files.map { it.absolutePath }
        },
    )
}
