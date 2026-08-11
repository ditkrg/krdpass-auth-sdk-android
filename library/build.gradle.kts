import kotlinx.validation.KotlinApiBuildTask
import kotlinx.validation.KotlinApiCompareTask

plugins {
    // AGP 9+ provides Kotlin built-in (the `kotlin { }` DSL below), so no standalone
    // org.jetbrains.kotlin.android plugin is applied.
    id("com.android.library")
    alias(libs.plugins.vanniktech.maven.publish)
    alias(libs.plugins.detekt)
    // Picked up by the publish plugin, which would otherwise ship an empty javadoc jar.
    alias(libs.plugins.dokka)
    // apply false: this only needs to put the plugin jar (and its KotlinApiBuildTask /
    // KotlinApiCompareTask classes) on this build script's classpath. Its own apply()
    // entry point is never invoked -- see below.
    alias(libs.plugins.binary.compatibility.validator) apply false
}

kotlin {
    jvmToolchain(17)
    explicitApi()
}

// API-parity guard for the cross-SDK public-API constraint.
//
// Applying the `org.jetbrains.kotlinx.binary-compatibility-validator` Gradle plugin normally
// (`alias(libs.plugins.binary.compatibility.validator)` with no `apply false`) does not work
// in this repo: the plugin's Android support only activates
// via `pluginManager.withPlugin("kotlin-android")`
// (BinaryCompatibilityValidatorPlugin.kt:131 in the 0.18.1 sources), and AGP 9's built-in
// Kotlin support (see the plugins block above) hard-fails the build if
// `org.jetbrains.kotlin.android` is ever applied: "The 'org.jetbrains.kotlin.android' plugin is
// no longer required for Kotlin support since AGP 9.0." Confirmed upstream, still open:
// https://github.com/Kotlin/binary-compatibility-validator/issues/312
//
// The plugin's own README points at its replacement, the Kotlin Gradle plugin's built-in
// `kotlin.abiValidation {}`. That is *also* broken for a plain (non-multiplatform) Android
// library on AGP 9 built-in Kotlin: it registers `checkKotlinAbi` / `updateKotlinAbi`, but
// wires zero compilation targets, so both fail at execution with "Cannot query the value of
// this provider ... referenceDumpDir" (verified against the Kotlin and AGP versions this
// repo pins, see gradle/libs.versions.toml and settings.gradle.kts).
//
// So this wires BCV's own dump/compare task types (still pinned to a known-good version)
// straight to the release variant's compiled classes --
// exactly what BCV's Android auto-configuration does internally, just without the plugin-id
// gate that AGP 9 blocks. Baseline lives in api/library.api next to this build file.
val apiBaselineFile = layout.projectDirectory.file("api/library.api")

// The dump worker (kotlinx.validation.AbiBuildWorker) needs ASM + kotlin-metadata-jvm on its
// classpath to read the compiled classes; normally BCV's own apply() wires this in, which we
// skip (see above), so it is reproduced here the same way BCV itself builds it.
val bcvRuntimeClasspath: Configuration = configurations.create("bcvRuntimeClasspath") {
    isCanBeResolved = true
    isCanBeConsumed = false
}
dependencies {
    bcvRuntimeClasspath(libs.asm)
    bcvRuntimeClasspath(libs.asm.tree)
    bcvRuntimeClasspath(libs.kotlin.metadata.jvm)
}

afterEvaluate {
    val kotlinClasses = tasks.named("compileReleaseKotlin").map { it.outputs.files }
    val javaClasses = tasks.named("compileReleaseJavaWithJavac").map { it.outputs.files }

    val apiBuild = tasks.register<KotlinApiBuildTask>("apiBuild") {
        inputClassesDirs.from(kotlinClasses)
        inputClassesDirs.from(javaClasses)
        outputApiFile.set(layout.buildDirectory.file("bcv/library.api"))
        runtimeClasspath.from(bcvRuntimeClasspath)
    }

    tasks.register<KotlinApiCompareTask>("apiCheck") {
        group = "verification"
        description = "Checks the public API surface against the committed baseline (api/library.api)."
        projectApiFile.set(apiBaselineFile)
        generatedApiFile.set(apiBuild.flatMap { it.outputApiFile })
    }
    tasks.named("check") { dependsOn("apiCheck") }

    tasks.register<Copy>("apiDump") {
        group = "other"
        description = "Regenerates the public API baseline (api/library.api)."
        from(apiBuild.flatMap { it.outputApiFile })
        into(layout.projectDirectory.dir("api"))
    }
}

// Static analysis: minimal ruleset on top of detekt's defaults, with a baseline of manually
// curated suppressions, each a considered decision with its reasoning written next to it (see
// config/detekt/baseline.xml). A finding that is not listed there fails the build.
detekt {
    buildUponDefaultConfig = true
    config.setFrom(files("$rootDir/config/detekt/detekt.yml"))
    baseline = file("$rootDir/config/detekt/baseline.xml")
}

android {
    // Deliberately NOT krd.pass.auth: the Flutter plugin module owns that namespace, and AGP
    // fails a consumer's manifest merge when two libraries share one. This only names the
    // generated R/BuildConfig package; the source package stays krd.pass.auth.
    namespace = "krd.pass.krdpass_auth"
    compileSdk = 36

    defaultConfig {
        minSdk = 24
        // A library never minifies (the consuming app's R8 does); these are the keep rules
        // consumers need.
        consumerProguardFiles("consumer-rules.pro")
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    // The library generates no BuildConfig fields; don't emit the class.
    buildFeatures {
        buildConfig = false
    }
}

// Published to Maven Central under the GROUP / POM_ARTIFACT_ID / VERSION_NAME in
// gradle.properties: consumers resolve it with `mavenCentral()`, no token. The plugin builds
// the sources + javadoc jars, GPG-signs every
// artifact, and uploads + releases through the Central Portal. Credentials/signing key come
// from ORG_GRADLE_PROJECT_* env vars in CI (see .github/workflows/release.yml).
//
// The sample-app runner may instead provide `krdpassLocalMavenRepo`. That publishes the same
// metadata and artifacts to an SDK-local repository for development consumers, without needing
// credentials or a signing key. It deliberately does not change the release path.
val localMavenRepository = providers.gradleProperty("krdpassLocalMavenRepo").orNull?.trim()?.takeIf { it.isNotEmpty() }

mavenPublishing {
    publishToMavenCentral()
    if (localMavenRepository == null) {
        signAllPublications()
    }

    pom {
        name.set("KRDPASS Auth SDK (Android)")
        description.set("Official native Android SDK for Sign in with KRDPASS, app-to-app SSO.")
        url.set("https://github.com/ditkrg/krdpass-auth-sdk-android")
        licenses {
            license {
                name.set("MIT License")
                url.set("https://opensource.org/licenses/MIT")
            }
        }
        developers {
            developer {
                id.set("ditkrg")
                name.set("KRDPASS Team")
                email.set("integration@pass.krd")
            }
        }
        scm {
            url.set("https://github.com/ditkrg/krdpass-auth-sdk-android")
            connection.set("scm:git:https://github.com/ditkrg/krdpass-auth-sdk-android.git")
            developerConnection.set("scm:git:ssh://git@github.com/ditkrg/krdpass-auth-sdk-android.git")
        }
    }
}

if (localMavenRepository != null) {
    publishing {
        repositories {
            maven {
                name = "localDevelopment"
                url = uri(localMavenRepository)
            }
        }
    }
}

dependencies {
    // api, not implementation: ComponentActivity, ActivityResultCaller and LifecycleOwner appear
    // in register(), so consumers need exactly these two on their compile classpath. Everything
    // else stays implementation because none of it appears in library/api/library.api.
    api(libs.androidx.activity)
    api(libs.androidx.lifecycle.common)
    implementation(libs.androidx.core)
    implementation(libs.androidx.lifecycle.runtime.ktx)
    implementation(libs.nimbus.jose.jwt)
    implementation(libs.squareup.okhttp)
    implementation(libs.squareup.okhttp.coroutines)
    testImplementation(libs.junit)
    testImplementation(libs.robolectric)
    testImplementation(libs.mockwebserver3)
}
