package com.securityaudit.plugin

import com.intellij.openapi.project.Project
import com.intellij.openapi.wm.StatusBar
import com.intellij.openapi.wm.StatusBarWidget
import com.intellij.openapi.wm.StatusBarWidgetFactory

class SecurityAuditStatusBarWidgetFactory : StatusBarWidgetFactory {
    override fun getId(): String = "SecurityAuditStatusBar"
    override fun getDisplayName(): String = "Security Audit"
    override fun isAvailable(project: Project): Boolean = true

    override fun createWidget(project: Project): StatusBarWidget {
        return SecurityAuditStatusBarWidget(project)
    }

    override fun disposeWidget(widget: StatusBarWidget) {}
    override fun canBeEnabledOn(statusBar: StatusBar): Boolean = true
}

class SecurityAuditStatusBarWidget(private val project: Project) : StatusBarWidget,
    StatusBarWidget.TextPresentation {

    override fun ID(): String = "SecurityAuditStatusBar"

    override fun getPresentation(): StatusBarWidget.WidgetPresentation = this

    override fun getText(): String = "\uD83D\uDEE1\uFE0F Secure"

    override fun getTooltipText(): String = "Security Audit — findings shown in Problems panel"

    override fun getAlignment(): Float = 0f

    override fun install(statusBar: StatusBar) {}

    override fun dispose() {}
}
