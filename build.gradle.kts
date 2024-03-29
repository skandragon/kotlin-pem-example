import org.jetbrains.kotlin.gradle.tasks.KotlinCompile

plugins {
    kotlin("jvm") version "1.8.0"
}

dependencies {
    implementation(kotlin("stdlib"))
    implementation("org.bouncycastle:bcprov-jdk15on:1.68")
    implementation("org.bouncycastle:bcpkix-jdk15on:1.68")
}

repositories {
    mavenCentral()
}

val compileKotlin: KotlinCompile by tasks
compileKotlin.kotlinOptions {
    jvmTarget = "19"
}

val compileTestKotlin: KotlinCompile by tasks
compileTestKotlin.kotlinOptions {
    jvmTarget = "19"
}
