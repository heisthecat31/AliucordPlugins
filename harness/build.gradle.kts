import org.jetbrains.kotlin.gradle.dsl.JvmTarget

// Desktop test harness: joins a real voice channel as a bot using the same core code as the plugin, and echoes
// back what it hears. Proves the MLS/DAVE implementation interoperates with official clients without a phone.
plugins {
    alias(libs.plugins.kotlin.jvm)
    application
}

kotlin {
    compilerOptions {
        jvmTarget = JvmTarget.JVM_21
    }
}

java {
    sourceCompatibility = JavaVersion.VERSION_21
    targetCompatibility = JavaVersion.VERSION_21
}

dependencies {
    implementation(project(":core"))
    implementation(libs.kotlin.stdlib)
    implementation("org.json:json:20260814")
}

application {
    mainClass.set("com.github.heisthecat.davevoice.harness.HarnessKt")
}
