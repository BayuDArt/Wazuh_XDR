#Suricata
!350 ar.conf
restart-ossec0 - restart-ossec.sh - 0
restart-ossec0 - restart-ossec.cmd - 0
restart-wazuh0 - restart-ossec.sh - 0
restart-wazuh0 - restart-ossec.cmd - 0
restart-wazuh0 - restart-wazuh - 0
restart-wazuh0 - restart-wazuh.exe - 0
remove-threat-Linux0 - remove-threat - 0
block-mikrotik-api0 - block-mikrotik - 0
cmd_zip_analyzer0 - zip_analyzer.py - 0
!167 agent.conf
  <agent_config>
    <localfile>
      <log_format>json</log_format>
      <location>/var/log/suricata/eve_filtered.json</location>
    </localfile>
  </agent_config>
