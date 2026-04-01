package com.securityaudit.plugin.actions

import com.intellij.openapi.actionSystem.AnAction
import com.intellij.openapi.actionSystem.AnActionEvent
import com.intellij.openapi.ui.Messages

class ShowReferenceAction : AnAction() {
    override fun actionPerformed(e: AnActionEvent) {
        val checkpointId = Messages.showInputDialog(
            e.project,
            "Enter checkpoint ID (e.g., SA-PY-01, SA-JS-06, SA-REACT-01):",
            "Security Audit — Show Reference",
            null
        )

        if (checkpointId.isNullOrBlank()) return

        Messages.showInfoMessage(
            "Reference lookup for $checkpointId.\n\n" +
                    "Use the MCP server tool 'explain_finding' for full reference documentation,\n" +
                    "or check the references/ directory in the security-audit-skill repository.",
            "Security Audit Reference"
        )
    }
}
