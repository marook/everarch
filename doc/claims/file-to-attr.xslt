<?xml version="1.0" encoding="UTF-8"?>
<!--
    file-to-attr.xslt contains a transformation rule for converting a
    file claim into an attr claim.

    This is usually being done within attr-rule claims which tell the
    attr index how to interpret different claim types in a key/value
    manner.
-->
<xsl:stylesheet
    version="1.0"
    xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
    xmlns:evr="https://evr.ma300k.de/claims/"
    xmlns:dc="http://purl.org/dc/terms/"
    >
  <xsl:output encoding="UTF-8"/>
  <xsl:template match="/evr:file">
    <evr:attr>
      <evr:a op="=" k="title" v="{@dc:title}"/>
      <evr:a op="=" k="size" v="{sum(evr:body/evr:slice/@size)}"/>
    </evr:attr>
  </xsl:template>
</xsl:stylesheet>
