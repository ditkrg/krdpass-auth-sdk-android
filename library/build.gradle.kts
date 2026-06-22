plugins {
    id("com.android.library")
    id("org.jetbrains.kotlin.android")
    id("maven-publish")
}

kotlin {
    jvmToolchain(17)
}

// Maven coordinates for the published core artifact. Published to GitHub Packages
// (see the publishing block below) as `krd.pass:krdpass-auth:<version>`; the wrappers
// and external consumers resolve that exact coordinate from the GitHub Packages repo.
group = "krd.pass"
version = "1.0.0"

android {
    namespace = "krd.pass.krdpass_auth"
    compileSdk = 35

    defaultConfig {
        minSdk = 24
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
        consumerProguardFiles("consumer-rules.pro")
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
        }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    publishing {
        singleVariant("release") {
            withSourcesJar()
        }
    }
}

publishing {
    publications {
        register<MavenPublication>("release") {
            groupId = "krd.pass"
            artifactId = "krdpass-auth"
            version = "1.0.0"
            afterEvaluate {
                from(components["release"])
            }
        }
    }
    repositories {
        // GitHub Packages (private-friendly, free, reuses GitHub access).
        // Publishing: CI sets GITHUB_ACTOR/GITHUB_TOKEN. Local: -Pgpr.user/-Pgpr.token.
        // Consumers add this same maven{} repo with their own GitHub PAT (read:packages).
        maven {
            name = "GitHubPackages"
            url = uri("https://maven.pkg.github.com/ditkrg/krdpass-auth-sdk-android")
            credentials {
                username = System.getenv("GITHUB_ACTOR") ?: (project.findProperty("gpr.user") as String? ?: "")
                password = System.getenv("GITHUB_TOKEN") ?: (project.findProperty("gpr.token") as String? ?: "")
            }
        }
    }
}

dependencies {
    implementation(libs.androidx.core.ktx)
    implementation(libs.androidx.activity.ktx)
    implementation(libs.androidx.lifecycle.runtime.ktx)
    implementation(libs.nimbus.jose.jwt)
    implementation(libs.squareup.okhttp)
    testImplementation(libs.junit)
    testImplementation(libs.robolectric)
    testImplementation(libs.mockwebserver)
    androidTestImplementation(libs.androidx.junit)
    androidTestImplementation(libs.androidx.espresso.core)
}
