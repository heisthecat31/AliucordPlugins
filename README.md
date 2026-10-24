# DaveVoice

Aliucord plugin that makes voice chat work again now that Discord requires DAVE (end-to-end encrypted calls).

Works: voice in servers, DMs and group calls, watching Go Live streams, screen sharing.
Video is sent as VP8.

## Install

Put `release/DaveVoice.zip` in `Aliucord/plugins` on your phone and restart Aliucord.

## Build

Needs JDK 21 and the Android SDK (`sdk.dir` in `local.properties` or `ANDROID_HOME`).

```
./gradlew :plugins:DaveVoice:make
```

Output: `plugins/DaveVoice/build/outputs/DaveVoice.zip`. Tests: `./gradlew :core:test`.
