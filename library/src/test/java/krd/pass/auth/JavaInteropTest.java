package krd.pass.auth;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.util.Collections;
import java.util.concurrent.atomic.AtomicReference;
import kotlin.Unit;
import org.junit.Test;

/**
 * Guards Java interop. Written in Java on purpose: it fails to compile if a public entry point
 * grows a kotlin.time.Duration parameter (its mangled JVM name is uncallable from Java) or if
 * signIn hands Java a kotlin.Result it cannot unwrap. Both calls take the earliest fail-fast
 * branch, so neither touches the network or the Android framework.
 */
public class JavaInteropTest {

    private static final long TIMEOUT_MILLIS = 300_000L;

    @Test
    public void authenticateIsCallableFromJava() {
        AtomicReference<AuthResult> seen = new AtomicReference<>();

        KrdpassAuth.authenticate(
                "urn:ietf:params:oauth:request_uri:example",
                "state-123",
                TIMEOUT_MILLIS,
                result -> {
                    seen.set(result);
                    return Unit.INSTANCE;
                });

        AuthResult result = seen.get();
        assertNotNull("authenticate must invoke the callback", result);
        assertTrue("the un-registered path is an error", result instanceof AuthResult.Error);
        assertNotNull("the error message must be readable", result.getMessage());
    }

    @Test
    public void signInIsCallableFromJavaAndItsResultIsReadable() {
        AtomicReference<KrdpassTokenResult> tokens = new AtomicReference<>();
        AtomicReference<Throwable> failure = new AtomicReference<>();

        KrdpassAuth.signIn(
                Collections.<String>emptyList(),
                TIMEOUT_MILLIS,
                new SignInCallback() {
                    @Override
                    public void onSuccess(KrdpassTokenResult result) {
                        tokens.set(result);
                    }

                    @Override
                    public void onFailure(Throwable error) {
                        failure.set(error);
                    }
                });

        // Both arms must be typed: Java gets a KrdpassTokenResult and a Throwable, not an opaque
        // kotlin.Result whose accessors carry mangled names.
        assertNull("no tokens on the fail-fast path", tokens.get());
        Throwable error = failure.get();
        assertNotNull("signIn must invoke onFailure", error);
        assertTrue(
                "the failure must be a typed KrdpassError",
                error instanceof KrdpassError.ConfigurationError);
        assertNotNull("the message must be readable from Java", error.getMessage());
    }

    @Test
    public void loggerAndConfigAreStaticFromJava() {
        // These must read as KrdpassAuth.setLogger(...), not KrdpassAuth.INSTANCE.setLogger(...).
        AtomicReference<String> seen = new AtomicReference<>();
        try {
            KrdpassAuth.setLogger((level, message) -> seen.set(level));
            KrdpassLogger installed = KrdpassAuth.getLogger();
            assertNotNull("the installed logger must be readable back", installed);
            installed.log("INFO", "hello");
            assertEquals("INFO", seen.get());
            KrdpassAuth.getConfig();
        } finally {
            KrdpassAuth.setLogger(null);
        }
        assertNull(KrdpassAuth.getLogger());
    }

    @Test
    public void tokenResultAccessorsAreCallableFromJava() {
        // Every accessor is unmangled only because no inline value class appears in the type.
        KrdpassTokenResult result =
                new KrdpassTokenResult(
                        "access-token", "id-token", "Bearer", 3600, "refresh-token", "openid", 0L);

        assertNotNull(result.getAccessToken());
        assertNotNull(result.getIdToken());
        assertNotNull(result.getRefreshToken());
        assertTrue("expiresIn is readable", result.getExpiresIn() == 3600);
        assertTrue("a receivedAt of 0 is long expired", result.isExpired(60L));
        assertTrue("toString must redact the access token",
                result.toString().contains("[REDACTED]"));
    }
}
