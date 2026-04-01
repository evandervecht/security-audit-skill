package com.securityaudit.plugin

import com.intellij.execution.configurations.GeneralCommandLine
import com.intellij.openapi.project.Project
import com.intellij.openapi.vfs.VirtualFile
import com.intellij.platform.lsp.api.LspServerSupportProvider
import com.intellij.platform.lsp.api.ProjectWideLspServerDescriptor

class SecurityAuditLspServerSupportProvider : LspServerSupportProvider {
    override fun fileOpened(
        project: Project,
        file: VirtualFile,
        serverStarter: LspServerSupportProvider.LspServerStarter
    ) {
        val supportedExtensions = setOf(
            "php", "js", "ts", "jsx", "tsx", "mjs", "cjs",
            "py", "java", "cs", "go", "rs", "rb",
            "vue", "swift", "kt", "tf", "bicep",
            "xml", "yaml", "yml", "json", "razor",
            "module", "install" // Drupal
        )

        val ext = file.extension?.lowercase() ?: return
        if (ext !in supportedExtensions) return

        serverStarter.ensureServerStarted(SecurityAuditLspServerDescriptor(project))
    }
}

class SecurityAuditLspServerDescriptor(project: Project) :
    ProjectWideLspServerDescriptor(project, "Security Audit") {

    override fun isSupportedFile(file: VirtualFile): Boolean {
        val supportedExtensions = setOf(
            "php", "js", "ts", "jsx", "tsx", "mjs", "cjs",
            "py", "java", "cs", "go", "rs", "rb",
            "vue", "swift", "kt", "tf", "bicep",
            "xml", "yaml", "yml", "json", "razor",
            "module", "install"
        )
        return file.extension?.lowercase() in supportedExtensions
    }

    override fun createCommandLine(): GeneralCommandLine {
        val settings = SecurityAuditSettings.getInstance()
        val serverPath = settings.lspServerPath

        return GeneralCommandLine("node", serverPath, "--stdio").apply {
            withParentEnvironmentType(GeneralCommandLine.ParentEnvironmentType.CONSOLE)
        }
    }
}
