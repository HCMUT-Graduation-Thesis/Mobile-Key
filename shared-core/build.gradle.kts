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

    // Bouncy Castle for ML-DSA (Standardized Dilithium)
    // Dùng bcprov chứa toàn bộ core crypto bao gồm PQC
    implementation(libs.bouncycastle.prov) 
    // Nếu vẫn thiếu, ta sẽ dùng thêm bcpqc (nhưng thường bcprov là đủ)
}
