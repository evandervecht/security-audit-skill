package com.example.imports

import javax.xml.parsers.DocumentBuilderFactory
import javax.xml.stream.XMLInputFactory

object XmlImport {
  // DTD support was switched on to accept a partner's legacy feed:
  // file:// and http:// external entities now resolve during parsing.
  def staxReader(xml: java.io.InputStream) = {
    val xif = XMLInputFactory.newInstance()
    xif.setProperty(XMLInputFactory.SUPPORT_DTD, true)
    xif.setProperty("javax.xml.stream.isSupportingExternalEntities", true)
    xif.createXMLStreamReader(xml)
  }

  def domParser() = {
    val dbf = DocumentBuilderFactory.newInstance()
    dbf.setFeature("http://xml.org/sax/features/external-general-entities", true)
    dbf.newDocumentBuilder()
  }
}
