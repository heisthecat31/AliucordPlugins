version = "0.1.0"
description = "Makes voice chat, Go Live and screen sharing work again with Discord's DAVE end-to-end encryption."

aliucord {
    changelog.set(
        """
        # 0.1.0
        * Voice chat works again (servers, DMs, group calls) with Discord's DAVE end-to-end encryption.
        * Watching Go Live streams and screen sharing work too (video is sent as VP8).
        """.trimIndent(),
    )
    deploy.set(false)
}

// core + the parts of BouncyCastle it uses, shrunk by R8 (see core/build.gradle.kts). A task reference rather than
// a "path" string: resolving the string during execution deadlocks Gradle.
evaluationDependsOn(":core")
val coreShrinkJar = project(":core").tasks.named("shrinkJar")

dependencies {
    implementation(files(rootDir.resolve("core/build/libs/core-shrunk.jar")).builtBy(coreShrinkJar))
}
