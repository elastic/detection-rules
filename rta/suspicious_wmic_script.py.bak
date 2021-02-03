# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License;
# you may not use this file except in compliance with the Elastic License.

# Name: Suspicious WMIC script execution
# RTA: suspicious_wmic_script.py
# Description: Uses the WMI command-line utility to execute built-in Windows commands which are unusual or unexpected.
# Reference: https://subt0x11.blogspot.com/2018/04/wmicexe-whitelisting-bypass-hacking.html
import os

from . import common

xsl_file = "test.xsl"
xsl_content = """<?xml version='1.0'?>
<stylesheet
xmlns="http://www.w3.org/1999/XSL/Transform" xmlns:ms="urn:schemas-microsoft-com:xslt"
xmlns:user="placeholder"
version="1.0">
<output method="text"/>
    <ms:script implements-prefix="user" language="JScript">
    <![CDATA[
    var r = new ActiveXObject("WScript.Shell").Run("ipconfig.exe");
    ]]> </ms:script>
</stylesheet>
"""


@common.requires_os(common.WINDOWS)
def main():
    common.log("Executing suspicious WMIC script")

    with open(xsl_file, "w") as f:
        f.write(xsl_content)

    # Many variations on this command. For example, -format:, /  format : , etc
    common.execute(["wmic.exe", "os", "get", "/format:" + xsl_file])

    os.remove(xsl_file)


if __name__ == "__main__":
    exit(main())
