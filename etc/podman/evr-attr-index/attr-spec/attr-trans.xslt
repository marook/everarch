<?xml version="1.0" encoding="UTF-8"?>
<!--
 * everarch - the hopefully ever lasting archive
 * Copyright (C) 2021-2023  Markus Peröbner
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
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

  <xsl:template match="evr:file" mode="claim">
    <evr:attr>
      <xsl:call-template name="common-attr"/>
      <evr:a op="+" k="class" v="file"/>
      <evr:a op="=" k="file-size" v="{format-number(sum(evr:body/evr:slice/@size), '0')}"/>
      <evr:a op="=" k="file" vf="claim-ref"/>
    </evr:attr>
  </xsl:template>

  <xsl:template match="*" mode="claim">
    <!-- default match in the end for unknown claims -->
    <evr:attr>
      <xsl:call-template name="common-attr"/>
      <evr:a op="+" k="class" v="unknown" />
      <evr:a op="+" k="unknown-claim-name" v="{local-name(.)}" />
      <evr:a op="+" k="unknown-claim-ns" v="{namespace-uri(.)}" />
    </evr:attr>
  </xsl:template>

  <!-- *****************************************************************
       common templates follow below this line
  -->
  <xsl:template name="common-attr">
    <xsl:call-template name="seed-attr"/>
    <xsl:if test="@dc:title">
      <evr:a op="=" k="title" v="{@dc:title}"/>
    </xsl:if>
  </xsl:template>

  <xsl:template name="seed-attr">
    <xsl:if test="@index-seed">
      <xsl:attribute name="index-seed"><xsl:value-of select="@index-seed"/></xsl:attribute>
    </xsl:if>
    <xsl:if test="not(@index-seed)">
      <xsl:attribute name="index-seed"><xsl:value-of select="count(preceding-sibling::*)"/></xsl:attribute>
    </xsl:if>
    <xsl:if test="@seed">
      <xsl:attribute name="seed"><xsl:value-of select="@seed"/></xsl:attribute>
    </xsl:if>
  </xsl:template>
</xsl:stylesheet>
