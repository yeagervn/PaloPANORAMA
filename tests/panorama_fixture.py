# -*- coding: utf-8 -*-
"""Fixture dung chung: 1 cau hinh PANORAMA gia lap DU DAC TRUNG de kiem chung ban port:
- Shared + 3 tang Device Group (DG-ALL -> DG-DC -> DG-HN)
- Object TRUNG TEN o nhieu tang (kiem tra luat 'DG gan hon thang')
- pre-rulebase va post-rulebase o ca Shared lan tung DG (kiem tra thu tu 0.3)
- <readonly> chua quan he parent-dg (dung nhu Panorama that)
- Template + Template Stack gan serial (kiem tra zone 0.6)
"""

PANORAMA_XML = """<config>
  <shared>
    <address>
      <entry name="OBJ-COMMON"><ip-netmask>10.0.0.1/32</ip-netmask></entry>
      <entry name="SHARED-ONLY"><ip-netmask>10.0.0.9/32</ip-netmask></entry>
      <entry name="WEB-SRV"><ip-netmask>192.168.100.10/32</ip-netmask></entry>
    </address>
    <address-group>
      <entry name="GR-SHARED"><static><member>SHARED-ONLY</member></static></entry>
    </address-group>
    <service>
      <entry name="SVC-443"><protocol><tcp><port>443</port></tcp></protocol></entry>
      <entry name="SVC-COMMON"><protocol><tcp><port>8000</port></tcp></protocol></entry>
    </service>
    <pre-rulebase><security><rules>
      <entry name="SHARED-PRE-DENY">
        <from><member>any</member></from><to><member>any</member></to>
        <source><member>10.66.66.66</member></source><destination><member>any</member></destination>
        <service><member>any</member></service><application><member>any</member></application>
        <action>deny</action>
      </entry>
    </rules></security></pre-rulebase>
    <post-rulebase><security><rules>
      <entry name="SHARED-POST-CATCHALL">
        <from><member>any</member></from><to><member>any</member></to>
        <source><member>any</member></source><destination><member>any</member></destination>
        <service><member>any</member></service><application><member>any</member></application>
        <action>allow</action>
      </entry>
    </rules></security></post-rulebase>
  </shared>
  <devices><entry name="localhost.localdomain">
    <device-group>
      <entry name="DG-ALL">
        <address>
          <entry name="OBJ-COMMON"><ip-netmask>10.1.1.1/32</ip-netmask></entry>
        </address>
        <pre-rulebase><security><rules>
          <entry name="DGALL-PRE-ALLOW">
            <from><member>trust</member></from><to><member>untrust</member></to>
            <source><member>10.20.20.20</member></source><destination><member>WEB-SRV</member></destination>
            <service><member>SVC-443</member></service><application><member>any</member></application>
            <action>allow</action>
          </entry>
        </rules></security></pre-rulebase>
        <post-rulebase><security><rules>
          <entry name="DGALL-POST">
            <from><member>any</member></from><to><member>any</member></to>
            <source><member>10.30.30.30</member></source><destination><member>any</member></destination>
            <service><member>any</member></service><application><member>any</member></application>
            <action>allow</action>
          </entry>
        </rules></security></post-rulebase>
      </entry>
      <entry name="DG-DC">
        <address>
          <entry name="OBJ-COMMON"><ip-netmask>10.2.2.2/32</ip-netmask></entry>
          <entry name="DC-RANGE"><ip-range>10.5.5.100-10.5.5.110</ip-range></entry>
        </address>
        <pre-rulebase><security><rules>
          <entry name="DGDC-PRE">
            <from><member>any</member></from><to><member>any</member></to>
            <source><member>DC-RANGE</member></source><destination><member>WEB-SRV</member></destination>
            <service><member>SVC-443</member></service><application><member>any</member></application>
            <action>allow</action>
          </entry>
        </rules></security></pre-rulebase>
        <post-rulebase><security><rules>
          <entry name="DGDC-POST">
            <from><member>any</member></from><to><member>any</member></to>
            <source><member>any</member></source><destination><member>any</member></destination>
            <service><member>SVC-COMMON</member></service><application><member>any</member></application>
            <action>allow</action>
          </entry>
        </rules></security></post-rulebase>
      </entry>
      <entry name="DG-HN">
        <address>
          <entry name="OBJ-COMMON"><ip-netmask>10.3.3.3/32</ip-netmask></entry>
          <entry name="HN-HOST"><ip-netmask>10.7.7.7/32</ip-netmask></entry>
        </address>
        <devices><entry name="001122334455"/><entry name="009988776655"/></devices>
        <pre-rulebase><security><rules>
          <entry name="DGHN-PRE">
            <from><member>any</member></from><to><member>any</member></to>
            <source><member>HN-HOST</member></source><destination><member>WEB-SRV</member></destination>
            <service><member>SVC-443</member></service><application><member>any</member></application>
            <action>allow</action>
          </entry>
        </rules></security></pre-rulebase>
        <post-rulebase><security><rules>
          <entry name="DGHN-POST">
            <from><member>any</member></from><to><member>any</member></to>
            <source><member>any</member></source><destination><member>any</member></destination>
            <service><member>any</member></service><application><member>any</member></application>
            <action>deny</action>
          </entry>
        </rules></security></post-rulebase>
      </entry>
    </device-group>
    <template>
      <entry name="TPL-BASE">
        <config><devices><entry name="localhost.localdomain">
          <network><interface><ethernet>
            <entry name="ethernet1/1"><layer3><ip><entry name="10.7.7.1/24"/></ip></layer3></entry>
            <entry name="ethernet1/2"><layer3><ip><entry name="192.168.100.1/24"/></ip></layer3></entry>
          </ethernet></interface></network>
          <vsys><entry name="vsys1"><zone>
            <entry name="trust"><network><layer3><member>ethernet1/1</member></layer3></network></entry>
            <entry name="untrust"><network><layer3><member>ethernet1/2</member></layer3></network></entry>
          </zone></entry></vsys>
        </entry></devices></config>
      </entry>
      <entry name="TPL-OTHER">
        <config><devices><entry name="localhost.localdomain">
          <network><interface><ethernet>
            <entry name="ethernet1/9"><layer3><ip><entry name="172.31.0.1/24"/></ip></layer3></entry>
          </ethernet></interface></network>
        </entry></devices></config>
      </entry>
    </template>
    <template-stack>
      <entry name="STACK-HN">
        <templates><member>TPL-BASE</member><member>TPL-OTHER</member></templates>
        <devices><entry name="001122334455"/></devices>
      </entry>
    </template-stack>
    <vsys><entry name="vsys1"/></vsys>
  </entry></devices>
  <readonly><devices><entry name="localhost.localdomain">
    <device-group>
      <entry name="DG-ALL"/>
      <entry name="DG-DC"><parent-dg>DG-ALL</parent-dg></entry>
      <entry name="DG-HN"><parent-dg>DG-DC</parent-dg></entry>
    </device-group>
  </entry></devices></readonly>
</config>"""
