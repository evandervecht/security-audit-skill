package com.securityaudit.plugin

import com.intellij.openapi.application.ApplicationManager
import com.intellij.openapi.components.PersistentStateComponent
import com.intellij.openapi.components.Service
import com.intellij.openapi.components.State
import com.intellij.openapi.components.Storage

@Service
@State(name = "SecurityAuditSettings", storages = [Storage("securityAudit.xml")])
class SecurityAuditSettings : PersistentStateComponent<SecurityAuditSettings.State> {

    data class State(
        var lspServerPath: String = "node_modules/@security-audit/lsp-server/dist/index.js",
        var minimumSeverity: String = "info",
        var enabledLanguages: MutableList<String> = mutableListOf(),
        var excludedCheckpoints: MutableList<String> = mutableListOf()
    )

    private var myState = State()

    override fun getState(): State = myState

    override fun loadState(state: State) {
        myState = state
    }

    var lspServerPath: String
        get() = myState.lspServerPath
        set(value) { myState.lspServerPath = value }

    var minimumSeverity: String
        get() = myState.minimumSeverity
        set(value) { myState.minimumSeverity = value }

    companion object {
        fun getInstance(): SecurityAuditSettings =
            ApplicationManager.getApplication().getService(SecurityAuditSettings::class.java)
    }
}
