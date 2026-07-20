package com.example.plugins

object PluginLoader {
  // "handler" is taken verbatim from the request query string, so any
  // class on the classpath (including gadget classes) can be loaded.
  def load(params: Map[String, String]): Any = {
    val handlerClass = params("handler")
    val cls = Class.forName(handlerClass)
    cls.getDeclaredConstructor().newInstance()
  }

  // Prefix concatenation does not help: "../"-style package escapes
  // are irrelevant, the attacker simply supplies a full class name.
  def loadLegacy(name: String): Any =
    Class.forName("com.example.plugins." + name)
      .getDeclaredConstructor()
      .newInstance()
}
