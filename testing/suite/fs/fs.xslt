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

  <xsl:key name="seed-desc" match="esd:seed-description" use="@seed"/>

  <xsl:template match="/esd:seed-description-set/esd:seed-description[//esd:attr/@k='file']">
    <efs:file-set>
      <!--
          add a broken file here which should be ignored
      -->
      <efs:file path="a/broken/file" size="" file-ref="" created="" last-modified=""/>

      <!--
          here is the good file for testing
      -->
      <efs:file last-modified="2022-10-10T12:13:14.000000Z">
        <xsl:attribute name="path">test-subdir<xsl:if test="esd:attr-index/esd:attr/@k='category'">/cat-<xsl:value-of select="key('seed-desc', esd:attr-index/esd:attr[@k='category']/@v)/esd:attr-index/esd:attr[@k='title']/@v"/></xsl:if>/<xsl:value-of select="esd:attr-index/esd:attr[@k='title']/@v"/></xsl:attribute>
        <xsl:attribute name="size"><xsl:value-of select="esd:attr-index/esd:attr[@k='file-size']/@v"/></xsl:attribute>
        <xsl:attribute name="file-ref"><xsl:value-of select="esd:attr-index/esd:attr[@k='file']/@v"/></xsl:attribute>
      </efs:file>
    </efs:file-set>
  </xsl:template>
</xsl:stylesheet>
