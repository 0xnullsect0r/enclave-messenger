plugins {
    id("com.android.application")
}

// Set by build.sh from the release version (`cargo xtask version`).
val enclaveVersion = System.getenv("ENCLAVE_VERSION") ?: "0.1.0"
val enclaveVersionCode = (System.getenv("ENCLAVE_VERSION_CODE") ?: "1").toInt()
// The release key (environment release-android); without it the build is
// signed with a key made for the run (CI dry runs), which installs but
// can't update a release.
val keystore = System.getenv("ANDROID_KEYSTORE_FILE")

android {
    namespace = "com.aricummings.enclave"
    compileSdk = 36
    ndkVersion = "28.2.13676358"

    defaultConfig {
        applicationId = "com.aricummings.enclave"
        minSdk = 28
        targetSdk = 36
        versionCode = enclaveVersionCode
        versionName = enclaveVersion
    }

    signingConfigs {
        create("release") {
            storeFile = file(keystore ?: "${layout.buildDirectory.get()}/run.keystore")
            storePassword = System.getenv("ANDROID_KEYSTORE_PASSWORD") ?: "enclave-run"
            keyAlias = System.getenv("ANDROID_KEY_ALIAS") ?: "enclave-run"
            keyPassword = System.getenv("ANDROID_KEY_PASSWORD") ?: "enclave-run"
        }
    }

    buildTypes {
        getByName("release") {
            isMinifyEnabled = false
            signingConfig = signingConfigs.getByName("release")
        }
    }

    // One APK per processor type, and one with both.
    splits {
        abi {
            isEnable = true
            reset()
            include("arm64-v8a", "x86_64")
            isUniversalApk = true
        }
    }

    sourceSets {
        getByName("main") {
            // Launcher icons from `cargo xtask icons`.
            res.srcDirs("src/main/res", "../../../packaging/icons/android")
            // libenclave_mobile.so for each ABI, from build.sh.
            jniLibs.srcDirs("src/main/jniLibs")
        }
    }

    packaging {
        // Stored uncompressed and 16 KB aligned (Android 15's page size).
        jniLibs {
            useLegacyPackaging = false
        }
    }
}
