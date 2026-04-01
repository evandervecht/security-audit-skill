package com.securityaudit.plugin

import com.intellij.openapi.options.Configurable
import javax.swing.*

class SecurityAuditSettingsConfigurable : Configurable {
    private var panel: JPanel? = null
    private var lspPathField: JTextField? = null
    private var severityCombo: JComboBox<String>? = null

    override fun getDisplayName(): String = "Security Audit"

    override fun createComponent(): JComponent {
        val settings = SecurityAuditSettings.getInstance()

        panel = JPanel().apply {
            layout = BoxLayout(this, BoxLayout.Y_AXIS)

            add(JLabel("LSP Server Path:"))
            lspPathField = JTextField(settings.lspServerPath, 50)
            add(lspPathField)

            add(Box.createVerticalStrut(10))

            add(JLabel("Minimum Severity:"))
            severityCombo = JComboBox(arrayOf("info", "warning", "error"))
            severityCombo!!.selectedItem = settings.minimumSeverity
            add(severityCombo)
        }

        return panel!!
    }

    override fun isModified(): Boolean {
        val settings = SecurityAuditSettings.getInstance()
        return lspPathField?.text != settings.lspServerPath ||
                severityCombo?.selectedItem != settings.minimumSeverity
    }

    override fun apply() {
        val settings = SecurityAuditSettings.getInstance()
        settings.lspServerPath = lspPathField?.text ?: settings.lspServerPath
        settings.minimumSeverity = severityCombo?.selectedItem as? String ?: settings.minimumSeverity
    }

    override fun reset() {
        val settings = SecurityAuditSettings.getInstance()
        lspPathField?.text = settings.lspServerPath
        severityCombo?.selectedItem = settings.minimumSeverity
    }
}
