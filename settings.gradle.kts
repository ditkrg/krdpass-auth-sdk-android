pluginManagement {
    repositories {
        google {
            content {
                includeGroupByRegex("com\\.android.*")
                includeGroupByRegex("com\\.google.*")
                includeGroupByRegex("androidx.*")
            }
        }
        mavenCentral()
        gradlePluginPortal()
    }
    plugins {
        // AGP 9+ ships Kotlin built-in, so no separate kotlin.android plugin is declared.
        id("com.android.library") version "9.3.1"
    }
}

plugins {
    // Toolchain download repositories so jvmToolchain(17) auto-provisioning is reproducible
    // across machines/CI (and not a Gradle 10 deprecation).
    id("org.gradle.toolchains.foojay-resolver-convention") version "1.0.0"
}

dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        google()
        mavenCentral()
    }
}

rootProject.name = "krdpass-auth-sdk-android"
include(":library")
