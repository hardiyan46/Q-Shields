# Direktori Skrip Active Response Kustom Q-Shields

Tempatkan skrip Active Response kustom di folder ini (`./wazuh/active-response/`).
Folder ini di-mount ke `/var/ossec/active-response/bin/qshields` di dalam container `wazuh.manager`
agar tidak menimpa skrip bawaan Wazuh di `/var/ossec/active-response/bin`.
