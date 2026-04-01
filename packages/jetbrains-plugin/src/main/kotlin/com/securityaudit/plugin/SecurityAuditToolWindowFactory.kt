package com.securityaudit.plugin

import com.intellij.openapi.project.Project
import com.intellij.openapi.wm.ToolWindow
import com.intellij.openapi.wm.ToolWindowFactory
import com.intellij.ui.content.ContentFactory
import javax.swing.*
import javax.swing.tree.DefaultMutableTreeNode
import javax.swing.tree.DefaultTreeModel

class SecurityAuditToolWindowFactory : ToolWindowFactory {
    override fun createToolWindowContent(project: Project, toolWindow: ToolWindow) {
        val panel = SecurityAuditToolWindowPanel(project)
        val content = ContentFactory.getInstance().createContent(panel.component, "Findings", false)
        toolWindow.contentManager.addContent(content)
    }
}

class SecurityAuditToolWindowPanel(private val project: Project) {
    private val rootNode = DefaultMutableTreeNode("Security Audit Findings")
    private val treeModel = DefaultTreeModel(rootNode)
    private val tree = JTree(treeModel)

    val component: JComponent
        get() {
            val panel = JPanel().apply {
                layout = BoxLayout(this, BoxLayout.Y_AXIS)

                // Toolbar
                val toolbar = JPanel().apply {
                    layout = BoxLayout(this, BoxLayout.X_AXIS)
                    add(JButton("Refresh").apply {
                        addActionListener { refreshFindings() }
                    })
                    add(Box.createHorizontalGlue())
                    add(JLabel("Findings are populated by the LSP server"))
                }
                add(toolbar)

                // Tree view
                val scrollPane = JScrollPane(tree)
                add(scrollPane)
            }

            // Initial state
            rootNode.add(DefaultMutableTreeNode("Open a supported file to see security findings"))
            treeModel.reload()

            return panel
        }

    private fun refreshFindings() {
        rootNode.removeAllChildren()
        rootNode.add(DefaultMutableTreeNode("Diagnostics are provided by the LSP server in the editor"))
        rootNode.add(DefaultMutableTreeNode("Check the Problems panel (Alt+6) for security findings"))
        treeModel.reload()
    }
}
