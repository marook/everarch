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
    xmlns:ui="https://evr.ma300k.de/attr-ui/"
    exclude-result-prefixes="ui"
    >
  <xsl:output encoding="UTF-8"/>

  <xsl:template match="/ui:attr-ui-spec">
    <interface>
      <object id="root" class="GtkApplicationWindow">
        <property name="visible">True</property>
        <property name="title">evr-attr-ui</property>

        <child>
          <object class="GtkScrolledWindow">
            <property name="visible">True</property>
            <child>
              <object class="GtkBox">
                <property name="visible">True</property>
                <property name="orientation">vertical</property>
                <property name="margin-start">5</property>
                <property name="margin-end">5</property>
                <property name="margin-top">5</property>
                <property name="margin-bottom">5</property>
                <property name="spacing">20</property>

                <xsl:for-each select="ui:root/*">
                  <child>
                    <xsl:apply-templates select="." mode="root-view"/>
                  </child>
                </xsl:for-each>
              </object>
            </child>
          </object>
        </child>
      </object>
    </interface>
  </xsl:template>

  <xsl:template match="ui:form" mode="root-view">
    <object class="GtkBox">
      <property name="visible">True</property>
      <property name="orientation">vertical</property>
      <property name="spacing">10</property>
      
      <xsl:for-each select="ui:fields/*">
        <child>
          <xsl:apply-templates select="." mode="field-view"/>
        </child>
      </xsl:for-each>

      <child>
        <object class="GtkButton">
          <property name="visible">True</property>
          <property name="label">save</property>
          <property name="halign">end</property>
          <style>
            <class name="suggested-action"/>
          </style>
          <signal name="clicked" handler="submit"/>
        </object>
      </child>
    </object>
  </xsl:template>

  <xsl:template match="ui:text" mode="field-view">
    <object class="GtkBox">
      <property name="visible">True</property>
      <property name="orientation">vertical</property>
      <property name="spacing">5</property>
      <child>
        <object class="GtkLabel">
          <property name="visible">True</property>
          <property name="halign">start</property>
          <property name="label">
            <xsl:value-of select="@k" />
          </property>
        </object>
      </child>
      <child>
        <object class="GtkEntry">
          <property name="visible">True</property>
        </object>
      </child>
    </object>
  </xsl:template>

  <xsl:template match="ui:date" mode="field-view">
    <object class="GtkBox">
      <property name="visible">True</property>
      <property name="orientation">vertical</property>
      <property name="spacing">2</property>
      <child>
        <object class="GtkLabel">
          <property name="visible">True</property>
          <property name="halign">start</property>
          <property name="label">
            <xsl:value-of select="@k" />
          </property>
        </object>
      </child>
      <child>
        <object class="GtkBox">
          <property name="visible">True</property>
          <property name="orientation">horizontal</property>
          <property name="spacing">2</property>

          <child>
            <object class="GtkEntry">
              <property name="visible">True</property>
              <property name="placeholder-text">YYYY-MM-DD<xsl:if test="@year-optional='true'"> or MM-DD</xsl:if>
              </property>
            </object>
            <packing>
              <property name="expand">True</property>
            </packing>
          </child>
        </object>
      </child>
    </object>
  </xsl:template>

  <xsl:template match="ui:seed-ref" mode="field-view">
    <object class="GtkBox">
      <property name="visible">True</property>
      <property name="orientation">vertical</property>
      <property name="spacing">2</property>
      <child>
        <object class="GtkLabel">
          <property name="visible">True</property>
          <property name="halign">start</property>
          <property name="label">
            <xsl:value-of select="@k" />
          </property>
        </object>
      </child>
      <child>
        <object class="GtkComboBox">
          <property name="visible">True</property>
        </object>
      </child>
    </object>
  </xsl:template>
</xsl:stylesheet>
