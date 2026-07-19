import kotlinx.validation.KotlinApiBuildTask
import kotlinx.validation.KotlinApiCompareTask

plugins {
    // AGP 9+ provides Kotlin built-in (the `kotlin { }` DSL below), so the standalone
    // org.jetbrains.kotlin.android plugin is no longer applied. Compiler plugins like
    // serialization are still applied separately.
    id("com.android.library")
    alias(libs.plugins.kotlin.serialization)
    alias(libs.plugins.vanniktech.maven.publish)
    alias(libs.plugins.detekt)
    // apply false: this only needs to put the plugin jar (and its KotlinApiBuildTask /
    // KotlinApiCompareTask classes) on this build script's classpath. Its own apply()
    // entry point is never invoked -- see the long comment below for why.
    alias(libs.plugins.binary.compatibility.validator) apply false
}

kotlin {
    jvmToolchain(17)
    explicitApi()
}

// API-parity guard for the cross-SDK public-API constraint.
//
// The modernization plan asked for the `org.jetbrains.kotlinx.binary-compatibility-validator`
// Gradle plugin applied normally (`alias(libs.plugins.binary.compatibility.validator)` with no
// `apply false`). That does not work in this repo: the plugin's Android support only activates
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
// this provider ... referenceDumpDir" (verified locally against Kotlin 2.4.0 / AGP 9.2.0).
//
// So this wires BCV's own dump/compare task types (the real JetBrains artifact the plan named,
// still pinned to a known-good version) straight to the release variant's compiled classes --
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
    bcvRuntimeClasspath("org.ow2.asm:asm:9.6")
    bcvRuntimeClasspath("org.ow2.asm:asm-tree:9.6")
    bcvRuntimeClasspath("org.jetbrains.kotlin:kotlin-metadata-jvm:${libs.versions.kotlin.get()}")
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

    tasks.register("apiDump") {
        group = "other"
        description = "Regenerates the public API baseline (api/library.api)."
        dependsOn(apiBuild)
        doLast {
            val generated = apiBuild.get().outputApiFile.get().asFile
            apiBaselineFile.asFile.parentFile.mkdirs()
            generated.copyTo(apiBaselineFile.asFile, overwrite = true)
        }
    }
}

// Static analysis: minimal ruleset on top of detekt's defaults, with a generated baseline so
// pre-existing findings don't fail the build. New code is still checked against the full
// default ruleset; only issues present when the baseline was generated are suppressed.
detekt {
    buildUponDefaultConfig = true
    config.setFrom(files("$rootDir/config/detekt/detekt.yml"))
    baseline = file("$rootDir/config/detekt/baseline.xml")
}

android {
    namespace = "krd.pass.krdpass_auth"
    compileSdk = 36

    defaultConfig {
        minSdk = 24
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
        consumerProguardFiles("consumer-rules.pro")
    }

    // A library must not minify: the consuming app's R8 does that. The keep rules consumers
    // need ship via consumerProguardFiles("consumer-rules.pro") above.
    buildTypes {
        release {
            isMinifyEnabled = false
        }
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

// Published to Maven Central as `krd.pass:krdpass-auth:<version>`: consumers resolve it with
// `mavenCentral()`, no token. The plugin builds the sources + javadoc jars, GPG-signs every
// artifact, and uploads + releases through the Central Portal. Credentials/signing key come
// from ORG_GRADLE_PROJECT_* env vars in CI (see .github/workflows/release.yml).
mavenPublishing {
    publishToMavenCentral()
    signAllPublications()

    coordinates("krd.pass", "krdpass-auth", "1.1.0")

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

dependencies {
    implementation(libs.androidx.core.ktx)
    implementation(libs.androidx.activity.ktx)
    implementation(libs.androidx.lifecycle.runtime.ktx)
    implementation(libs.nimbus.jose.jwt)
    implementation(libs.kotlinx.serialization.json)
    implementation(libs.squareup.okhttp)
    testImplementation(libs.junit)
    testImplementation(libs.robolectric)
    testImplementation(libs.mockwebserver)
    androidTestImplementation(libs.androidx.junit)
    androidTestImplementation(libs.androidx.espresso.core)
}
