package com.securityaudit.plugin.actions

import com.intellij.openapi.actionSystem.AnAction
import com.intellij.openapi.actionSystem.AnActionEvent
import com.intellij.openapi.actionSystem.CommonDataKeys
import com.intellij.openapi.ui.Messages

class ScanFileAction : AnAction() {
    override fun actionPerformed(e: AnActionEvent) {
        val file = e.getData(CommonDataKeys.VIRTUAL_FILE)
        if (file == null) {
            Messages.showWarningDialog("No file is currently open.", "Security Audit")
            return
        }

        Messages.showInfoMessage(
            "Security diagnostics for ${file.name} are provided in real-time by the LSP server.\n\n" +
                    "Check the Problems panel (Alt+6) for findings.",
            "Security Audit"
        )
    }

    override fun update(e: AnActionEvent) {
        e.presentation.isEnabled = e.getData(CommonDataKeys.VIRTUAL_FILE) != null
    }
}
