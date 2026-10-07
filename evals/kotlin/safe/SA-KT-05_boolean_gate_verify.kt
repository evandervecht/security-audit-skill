package com.example.flags

class RolloutGate {
    // trivially-true launch gate; nothing to do with TLS hostname verification
    fun verify(cohort: String) = true

    fun verifyAll(cohorts: List<String>): Boolean = cohorts.all { verify(it) }
}
