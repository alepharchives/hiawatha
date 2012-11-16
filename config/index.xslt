<?xml version="1.0" ?>
<xsl:stylesheet	version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">

<xsl:output method="html" encoding="utf-8" doctype-public="-//W3C//DTD HTML 4.01//EN" doctype-system="http://www.w3.org/TR/html4/strict.dtd" />

<xsl:template match="/index">
<html>

<head>
<title><xsl:value-of select="hostname" /> : <xsl:value-of select="request_uri" /></title>
<style type="text/css">
	body {
		background-color:#ffffff;
		font-family:sans-serif;
		font-size:12px;
		padding:25px 100px 25px 100px;
	}

	h1 {
		letter-spacing:5px;
	}

	table.list {
		width:100%;
		padding:20px;
		border-spacing:0;
		border:1px solid #c0c0c0;
		background-color:#f4f4f4;
		border-radius:15px;
		box-shadow:6px 12px 10px #808080;
	}

	tr.header th {
		border-bottom:1px solid #e0e0e0;
		letter-spacing:1px;
	}
	tr.header th.timestamp {
		width:160px;
	}
	tr.header th.size {
		width:140px;
	}

	tr.file td {
		border-bottom:1px solid #e0e0e0;
		padding:2px 15px;
	}
	tr.file:hover td {
		background-color:#ffffc0;
		cursor:pointer;
	}
	tr.file:nth-child(even) {
		background-color:#e8e8f0;
	}
	tr.file:nth-child(odd) {
		background-color:#f0f0f8;
	}
	tr.file td.size {
		text-align:right;
	}
	tr.file td.dir a {
		color:#0000ff;
	}
	tr.file td.file a {
		color:#4080ff;
	}

	tr.bottom td {
		padding:20px 15px 0 15px;
	}
	tr.bottom td.totalsize {
		text-align:right;
	}

	a {
		text-decoration:none;
	}

	div.powered {
		margin-top:40px;
		text-align:center;
		color:#808080;
	}
	div.powered a {
		color:#80b0c0;
	}
</style>
</head>

<body>
<h1><xsl:value-of select="hostname" /> : <xsl:value-of select="request_uri" /></h1>
<table class="list">
<tr class="header">
	<th class="filename">filename</th>
	<th class="timestamp">timestamp</th>
	<th class="size">filesize</th>
</tr>
<xsl:for-each select="files/file">
<tr class="file" onClick="javascript:window.location.href='{@url_encoded}'">
	<td class="{@type}"><a href="{@url_encoded}"><xsl:value-of select="." /></a></td>
	<td><xsl:value-of select="@timestamp" /></td>
	<td class="size"><xsl:value-of select="@size" /></td>
</tr>
</xsl:for-each>
<tr class="bottom">
	<td class="totalfiles"><xsl:value-of select="count(files/file)" /> files</td>
	<td></td>
	<td class="totalsize"><xsl:value-of select="total_size" /></td>
</tr>
</table>
<div class="powered">Powered by <a href="http://www.hiawatha-webserver.org/" target="_blank"><xsl:value-of select="software" /></a></div>
</body>

</html>
</xsl:template>

</xsl:stylesheet>
