package com.example.imports

import javax.xml.parsers.DocumentBuilderFactory
import javax.xml.stream.XMLInputFactory

object XmlImport {
  // OWASP XXE hardening: no DTDs, no external entity resolution.
  def staxReader(xml: java.io.InputStream) = {
    val xif = XMLInputFactory.newInstance()
    xif.setProperty(XMLInputFactory.SUPPORT_DTD, false)
    xif.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, false)
    xif.createXMLStreamReader(xml)
  }

  def domParser() = {
    val dbf = DocumentBuilderFactory.newInstance()
    dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)
    dbf.setFeature("http://xml.org/sax/features/external-general-entities", false)
    dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false)
    dbf.setXIncludeAware(false)
    dbf.setExpandEntityReferences(false)
    dbf.newDocumentBuilder()
  }
}
