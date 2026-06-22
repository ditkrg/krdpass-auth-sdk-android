# Consumer ProGuard rules for library
-keep class krd.pass.auth.** { *; }

# Nimbus JOSE+JWT loads crypto providers and algorithm handlers via reflection.
# Without this, R8 in a consumer's minified release build can strip them and
# silently break ID-token signature verification (verifyToken / signIn nonce check).
-keep class com.nimbusds.** { *; }
-dontwarn com.nimbusds.**
