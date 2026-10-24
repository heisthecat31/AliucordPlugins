# Everything in the core is API for the plugin (or the desktop harness).
-keep class com.github.heisthecat.davevoice.core.** { *; }

# MlsSession copies a Group via its private successor() (mlspp copies State by value).
-keepclassmembers class org.bouncycastle.mls.protocol.Group {
    *** successor();
}

# MLSInputStream/MLSOutputStream (de)serialise by reflection: codec classes need their (stream) constructors.
-keepclassmembers class org.bouncycastle.mls.** implements org.bouncycastle.mls.codec.MLSInputStream$Readable {
    <init>(org.bouncycastle.mls.codec.MLSInputStream);
}
-keep class org.bouncycastle.mls.** implements org.bouncycastle.mls.codec.MLSInputStream$Readable

-dontobfuscate
-dontoptimize
-keepattributes *
-dontwarn **
