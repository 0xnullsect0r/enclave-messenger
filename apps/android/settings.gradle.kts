// Enclave for Android (milestone A1): the app is the Rust library
// libenclave_mobile.so (nym/enclave-mobile) on a NativeActivity, built for
// arm64-v8a and x86_64 by apps/android/build.sh.
pluginManagement {
    repositories {
        google()
        mavenCentral()
        gradlePluginPortal()
    }
}
dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        google()
        mavenCentral()
    }
}
rootProject.name = "Enclave"
include(":app")
