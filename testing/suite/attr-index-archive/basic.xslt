<?xml version="1.0" encoding="UTF-8"?>
<!--
    basic.xslt contains a transformation rule just keeping evr claims.
-->
<xsl:stylesheet
    version="1.0"
    xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
    xmlns:evr="https://evr.ma300k.de/claims/"
    xmlns:dc="http://purl.org/dc/terms/"
    >
  <xsl:output encoding="UTF-8"/>

  <xsl:template match="/evr:claim-set">
    <evr:claim-set dc:created="{@dc:created}">
      <xsl:apply-templates mode="claim"/>
    </evr:claim-set>
  </xsl:template>

  <xsl:template match="evr:attr" mode="claim">
    <xsl:copy-of select="."/>
  </xsl:template>

  <xsl:template match="evr:archive" mode="claim">
    <xsl:copy-of select="."/>
  </xsl:template>
</xsl:stylesheet>
