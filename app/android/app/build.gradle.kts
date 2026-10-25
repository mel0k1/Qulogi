plugins {
    id("com.android.application")
    id("kotlin-android")
    id("dev.flutter.flutter-gradle-plugin")
}

android {
    namespace = "ru.qulogi.app"
    compileSdk = 36

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    kotlinOptions {
        jvmTarget = "17"
    }

    defaultConfig {
        applicationId = "ru.qulogi.app"
        minSdk = 29
        targetSdk = 36
        versionCode = 3
        versionName = "0.3.0"
    }

    buildTypes {
        release {
            // TODO(mel0k1): switch to a real signing config before publishing.
            signingConfig = signingConfigs.getByName("debug")
        }
    }
}

flutter {
    source = "../.."
}

dependencies {
    // gomobile AAR built by CI (gomobile bind -o app/android/app/libs/mobile.aar ./mobile)
    implementation(fileTree(mapOf("dir" to "libs", "include" to listOf("*.aar", "*.jar"))))
}
