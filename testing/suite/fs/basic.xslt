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

  <xsl:template match="/evr:claim-set">
    <evr:claim-set dc:created="{@dc:created}">
      <xsl:apply-templates/>
    </evr:claim-set>
  </xsl:template>

  <xsl:template match="evr:attr">
    <xsl:copy-of select="."/>
  </xsl:template>

  <xsl:template match="evr:file">
    <evr:attr>
      <xsl:call-template name="seed-attr"/>
      <evr:a op="=" k="title" v="{@dc:title}"/>
      <evr:a op="=" k="file-size" v="{sum(evr:body/evr:slice/@size)}"/>
      <evr:a op="=" k="file" vf="claim-ref"/>
    </evr:attr>
  </xsl:template>

  <xsl:template name="seed-attr">
    <xsl:attribute name="index-seed"><xsl:value-of select="count(preceding-sibling::*)"/></xsl:attribute>
    <xsl:if test="@seed">
      <xsl:attribute name="seed"><xsl:value-of select="@seed"/></xsl:attribute>
    </xsl:if>
  </xsl:template>
</xsl:stylesheet>
