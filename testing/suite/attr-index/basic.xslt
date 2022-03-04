<?xml version="1.0" encoding="UTF-8"?>
<!--
    basic.xslt contains a transformation rule just keeping attr claims.
-->
<xsl:stylesheet
    version="1.0"
    xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
    xmlns:evr="https://evr.ma300k.de/claims/"
    xmlns:dc="http://purl.org/dc/terms/"
    >
  <xsl:output encoding="UTF-8"/>
  <xsl:template match="/evr:attr">
    <xsl:copy>
        <xsl:apply-templates select="@*"/>
        <xsl:apply-templates/>
    </xsl:copy>
  </xsl:template>
</xsl:stylesheet>
