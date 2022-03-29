<?xml version='1.0'?>
<xsl:stylesheet version="1.0"
      xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
      xmlns:msxsl="urn:schemas-microsoft-com:xslt"
      xmlns:user="http://mycompany.com/mynamespace">

<xsl:output encoding="UTF-8" indent="yes" method="xml" />
<msxsl:script language="JScript" implements-prefix="user">
function xml(nodelist) 
{	
	var xhr=new ActiveXObject("Msxml2.XMLHttp.6.0");
	xhr.open("GET","http://127.0.0.1:8000",false);
	xhr.send();

	return nodelist.nextNode().xml;
}
</msxsl:script>
<xsl:template match="/">
   <xsl:value-of select="user:xml(.)"/>
</xsl:template>
</xsl:stylesheet>
