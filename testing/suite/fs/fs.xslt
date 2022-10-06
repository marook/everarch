<?xml version="1.0" encoding="UTF-8"?>
<!--
    fs.xslt contains transformation rules for evr-fs.
-->
<xsl:stylesheet
    version="1.0"
    xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
    xmlns:esd="https://evr.ma300k.de/seed-description/"
    xmlns:efs="https://evr.ma300k.de/files/"
    >
  <xsl:output encoding="UTF-8"/>

  <xsl:template match="/esd:seed-description">
    <efs:file-set>
      <efs:file>
        <xsl:attribute name="path">test-subdir/<xsl:value-of select="//attr[@k='title']/@v"/></xsl:attribute>
        <xsl:attribute name="size"><xsl:value-of select="//attr[@k='file-size']/@v"/></xsl:attribute>
        <xsl:attribute name="file-ref"><xsl:value-of select="//attr[@k='file']/@v"/></xsl:attribute>
      </efs:file>
    </efs:file-set>
  </xsl:template>
</xsl:stylesheet>
