import org.jetbrains.kotlin.gradle.dsl.JvmTarget

plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("org.jetbrains.kotlin.plugin.compose")
}

android {
    namespace = "com.token2.fidoparole"
    compileSdk = 36
    ndkVersion = "27.2.12479018"

    defaultConfig {
        applicationId = "com.ordanexa.fidoparole.mobile"
        minSdk = 26
        targetSdk = 36
        versionCode = 8
        versionName = "1.0.0"
        ndk { abiFilters += listOf("arm64-v8a", "armeabi-v7a", "x86_64") }
    }

    splits {
        abi {
            isEnable = true
            reset()
            include("arm64-v8a")
            isUniversalApk = true
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = true
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
            // Signing is configured outside the repo (keystore + passwords in CI secrets).
        }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    buildFeatures { compose = true; buildConfig = true }
    sourceSets["main"].java.srcDir(layout.buildDirectory.dir("generated/uniffi"))
    sourceSets["main"].jniLibs.srcDir(layout.buildDirectory.dir("rustJniLibs"))
    packaging { jniLibs { useLegacyPackaging = false } }
    testOptions { unitTests { isIncludeAndroidResources = true } }
}

kotlin { compilerOptions { jvmTarget.set(JvmTarget.JVM_17) } }

// ---- Rust core: build libfidoparole_ffi.so per ABI and generate the Kotlin bindings.
val repoRoot = rootProject.projectDir.parentFile
val rustProfile = (findProperty("rustProfile") as String?) ?: "release"
val buildRust by tasks.registering(Exec::class) {
    description = "Builds the Rust core (cargo-ndk) and generates Kotlin bindings (UniFFI)"
    workingDir = repoRoot
    inputs.dir(File(repoRoot, "core/src")); inputs.dir(File(repoRoot, "ffi/src"))
    inputs.file(File(repoRoot, "Cargo.lock"))
    outputs.dir(layout.buildDirectory.dir("rustJniLibs")); outputs.dir(layout.buildDirectory.dir("generated/uniffi"))
    environment("ANDROID_NDK_HOME", android.ndkDirectory.absolutePath)
    commandLine("bash", File(rootProject.projectDir, "build-rust.sh").absolutePath,
        layout.buildDirectory.get().asFile.absolutePath, rustProfile)
}
tasks.named("preBuild") { dependsOn(buildRust) }

dependencies {
    val composeBom = platform("androidx.compose:compose-bom:2025.12.01")
    implementation(composeBom)
    implementation("androidx.compose.material3:material3")
    implementation("androidx.compose.material:material-icons-extended")
    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.ui:ui-tooling-preview")
    debugImplementation("androidx.compose.ui:ui-tooling")
    implementation("androidx.activity:activity-compose:1.13.0")
    implementation("androidx.lifecycle:lifecycle-viewmodel-compose:2.9.4")
    implementation("androidx.lifecycle:lifecycle-process:2.9.4")
    implementation("androidx.core:core-ktx:1.17.0")
    // Saved PIN: Keystore key unlocked by fingerprint / screen lock.
    implementation("androidx.biometric:biometric:1.1.0")
    implementation("androidx.fragment:fragment-ktx:1.8.9")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.10.2")
    // UniFFI's Kotlin bindings call the Rust library through JNA.
    implementation("net.java.dev.jna:jna:5.17.0@aar")

    // JVM tests run the generated Kotlin bindings against the host build of the Rust library.
    testImplementation("junit:junit:4.13.2")
    testImplementation("net.java.dev.jna:jna:5.17.0")
    // Screenshots of the Compose UI on the JVM (Robolectric native graphics + Roborazzi).
    testImplementation("org.robolectric:robolectric:4.17")
    testImplementation("io.github.takahirom.roborazzi:roborazzi:1.76.0")
    testImplementation("io.github.takahirom.roborazzi:roborazzi-compose:1.76.0")
    testImplementation("androidx.compose.ui:ui-test-junit4")
    debugImplementation("androidx.compose.ui:ui-test-manifest")
}

tasks.withType<Test>().configureEach {
    dependsOn(buildRust)
    systemProperty("jna.library.path", File(repoRoot, "target/debug").absolutePath)
    systemProperty("roborazzi.test.record", "true")
    // Optional: a folder with Robolectric's android-all jar, for offline/rate-limited builds.
    (findProperty("robolectricDeps") as String?)?.let {
        systemProperty("robolectric.offline", "true")
        systemProperty("robolectric.dependency.dir", it)
    }
}
