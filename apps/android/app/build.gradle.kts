plugins {
    id("com.android.application")
}

// Set by build.sh from the release version (`cargo xtask version`).
val enclaveVersion = System.getenv("ENCLAVE_VERSION") ?: "0.1.4"
val enclaveVersionCode = (System.getenv("ENCLAVE_VERSION_CODE") ?: "1").toInt()
// The release key (environment release-android); without it the build is
// signed with a key made for the run (CI dry runs), which installs but
// can't update a release.
val keystore = System.getenv("ANDROID_KEYSTORE_FILE")?.takeIf { it.isNotEmpty() }
// The release key's passwords and alias, only with the release key (a dry
// run may have them set while it signs with the run's key).
fun releaseEnv(name: String): String =
    keystore?.let { System.getenv(name)?.takeIf { v -> v.isNotEmpty() } } ?: "enclave-run"

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

    buildFeatures {
        buildConfig = true
    }

    // fdroid: no Google code (UnifiedPush, or staying connected); the
    // release APKs. play: adds Google's push, off until chosen; the app
    // bundle for Google Play. Its Firebase project comes from the build's
    // environment (FCM_*, docs/10-push.md §5); without it the choice
    // isn't offered.
    flavorDimensions += "store"
    productFlavors {
        create("fdroid") {
            dimension = "store"
        }
        create("play") {
            dimension = "store"
            for (k in listOf("FCM_PROJECT_ID", "FCM_APP_ID", "FCM_API_KEY", "FCM_SENDER_ID")) {
                buildConfigField("String", k, "\"" + (System.getenv(k) ?: "") + "\"")
            }
        }
    }

    signingConfigs {
        create("release") {
            storeFile = file(keystore ?: "${layout.buildDirectory.get()}/run.keystore")
            storePassword = releaseEnv("ANDROID_KEYSTORE_PASSWORD")
            keyAlias = releaseEnv("ANDROID_KEY_ALIAS")
            keyPassword = releaseEnv("ANDROID_KEY_PASSWORD")
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

dependencies {
    "playImplementation"("com.google.firebase:firebase-messaging:25.1.3")
}
