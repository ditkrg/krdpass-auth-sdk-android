# No keep rule for krd.pass.auth: R8 already keeps whatever the consuming app references, and
# the public surface is pinned by library/api/library.api. Keeping the whole package would ship
# every internal class of a security library unshrunk and unobfuscated in every consumer's
# release build, which is backwards.

# Nimbus JOSE+JWT 10.x selects a JWS verifier through a direct factory, not by reflection, so
# R8's reachability analysis covers the RSA path on its own. These two are pinned anyway: they
# are the whole ID-token trust path, and a keep rule that turns out to be unnecessary costs two
# classes, while a missing one costs a runtime failure in ID-token signature verification
# (verifyToken, and the signIn nonce check).
-keep class com.nimbusds.jose.crypto.RSASSAVerifier { *; }
-keep class com.nimbusds.jose.crypto.factories.DefaultJWSVerifierFactory { *; }

# Nimbus references BouncyCastle and Tink for the EC, OKP and JWE algorithms this SDK never
# uses; neither is on the classpath. Silence those missing-class warnings rather than dragging
# two crypto libraries into every consumer. Scoped to the referencing packages so a genuinely
# missing class on the RS256 path still warns.
-dontwarn com.nimbusds.jose.crypto.impl.**
-dontwarn com.nimbusds.jose.jwk.**
-dontwarn org.bouncycastle.**
-dontwarn com.google.crypto.tink.**
