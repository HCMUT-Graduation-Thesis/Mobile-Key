plugins {
    kotlin("jvm")
}

kotlin {
    jvmToolchain(17)
}

java {
    sourceCompatibility = JavaVersion.VERSION_17
    targetCompatibility = JavaVersion.VERSION_17
}

dependencies {
    implementation(kotlin("stdlib"))

    // Bouncy Castle for ML-DSA (Dilithium)
    implementation(libs.bouncycastle.prov)
    implementation(libs.bouncycastle.pqc)
}
