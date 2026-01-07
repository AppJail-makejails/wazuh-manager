# Wazuh (manager)

The Wazuh server is the central component responsible for analyzing data collected from Wazuh agents and agentless devices. It detects threats, anomalies, and regulatory compliance violations in real time, generating alerts when suspicious activity is identified. Beyond detection, the Wazuh server enables centralized management by remotely configuring Wazuh agents and continuously monitoring their operational status.

wazuh.com

<img src="https://upload.wikimedia.org/wikipedia/commons/c/c3/Wazuh-Logo-2022.png?20230817165159" width="60%" height="auto" alt="wazuh logo">

## How to use this Makejail

### Deploy using appjail-director

**.env**:

```
DIRECTOR_PROJECT=wazuh-manager
```

**appjail-director.yml**:

```yaml
options:
  - osversion: '14.3-RELEASE'
  - copydir: 'user-files'
  - file: '/usr/local/etc/pkg/repos/Latest.conf'
  - template: 'template.conf'
services:
  wazuh-manager:
    makejail: gh+AppJail-makejails/wazuh-manager
    priority: 98
    options:
      - virtualnet: ':<random> address:10.0.0.80 default'
      - nat:
      - file: '/wazuh-config-mount'
      - file: '/entrypoint-scripts'
    environment:
      - WAZUH_NODE_NAME: 'manager'
      - WAZUH_CLUSTER_NODES: '10.0.0.80'
      - WAZUH_CLUSTER_BIND_ADDR: '10.0.0.80'
      - WAZUH_CLUSTER_KEY: '10451c28f859299128c8bb50dde28675'
      - WAZUH_INDEXER_HOSTS: '10.0.0.81:9200'
      - INDEXER_USERNAME: 'admin'
      - INDEXER_PASSWORD: 'admin'
      - API_USERNAME: 'wazuh-wui'
      - API_PASSWORD: 'MyS3cr37P450r.*-'
    volumes:
      - wazuh-data: /data
      - wazuh-indexer-connector-certs: /usr/local/etc/logstash/certs
      - wazuh-pkgcache: /var/cache/pkg
  beats:
    makejail: 'gh+AppJail-makejails/wazuh-manager --file beats.makejail'
    options:
      - virtualnet: ':<random> default'
      - nat:
    arguments:
      - logstash_addr: '10.0.0.81'
    volumes:
      - wazuh-logs: /var/ossec/logs
      - beats-data: /var/db/beats
volumes:
  wazuh-data:
    device: /var/appjail-volumes/wazuh/data
  wazuh-logs:
    device: /var/appjail-volumes/wazuh/data/logs
    options: ro
  wazuh-indexer-connector-certs:
    device: /var/appjail-volumes/wazuh/indexer-connector-certs
    options: ro
  wazuh-pkgcache:
    device: /var/appjail-volumes/wazuh/pkgcache
    type: nullfs
  beats-data:
    device: /var/appjail-volumes/wazuh/beats-data
    owner: 0
    group: 0
    mode: 0755
```

**template.conf**:

```
exec.clean
exec.start: "/bin/sh /etc/rc"
exec.stop: "/bin/sh /etc/rc.shutdown jail"
mount.devfs
allow.mount
allow.mount.nullfs
allow.mount.procfs
enforce_statfs: 1
mount.procfs
persist
```

**user-files/usr/local/etc/pkg/repos/Latest.conf**:

```
FreeBSD: {
  url: "pkg+https://pkg.FreeBSD.org/${ABI}/latest",
  mirror_type: "srv",
  signature_type: "fingerprints",
  fingerprints: "/usr/share/keys/pkg",
  enabled: yes
}
FreeBSD-kmods: {
  enabled: no
}
```

**user-files/wazuh-config-mount/etc/authd.pass**:

```
fhlc0egBAfx0vZMWoJig4bhZjPgxG8tKEM0yTBfd50Q
```

**user-files/wazuh-config-mount/etc/ossec.conf**:

```
<!--
  Wazuh - Manager - Default configuration.
  More info at: https://documentation.wazuh.com
  Mailing list: https://groups.google.com/forum/#!forum/wazuh
-->

<ossec_config>
  <global>
    <jsonout_output>yes</jsonout_output>
    <alerts_log>yes</alerts_log>
    <logall>no</logall>
    <logall_json>no</logall_json>
    <email_notification>no</email_notification>
    <smtp_server>smtp.example.wazuh.com</smtp_server>
    <email_from>wazuh@example.wazuh.com</email_from>
    <email_to>recipient@example.wazuh.com</email_to>
    <email_maxperhour>12</email_maxperhour>
    <email_log_source>alerts.log</email_log_source>
    <agents_disconnection_time>15m</agents_disconnection_time>
    <agents_disconnection_alert_time>0</agents_disconnection_alert_time>
  </global>

  <vulnerability-detection>
     <enabled>no</enabled>
     <index-status>yes</index-status>
     <feed-update-interval>60m</feed-update-interval>
  </vulnerability-detection>

  <indexer>
     <enabled>yes</enabled>
     <hosts>
        <host>https://127.0.0.1:9200</host>
     </hosts>
    <ssl>
      <certificate_authorities>
        <ca>/usr/local/etc/logstash/certs/root-ca.pem</ca>
      </certificate_authorities>
      <certificate>/usr/local/etc/logstash/certs/node-1.pem</certificate>
      <key>/usr/local/etc/logstash/certs/node-1-key.pem</key>
    </ssl>
  </indexer>

  <alerts>
    <log_alert_level>3</log_alert_level>
    <email_alert_level>12</email_alert_level>
  </alerts>

  <remote>
    <connection>secure</connection>
    <port>1514</port>
    <protocol>udp</protocol>
    <queue_size>131072</queue_size>
  </remote>

  <!-- Policy monitoring -->
  <rootcheck>
    <disabled>no</disabled>

    <!-- Frequency that rootcheck is executed - every 12 hours -->
    <frequency>43200</frequency>

    <rootkit_files>/var/ossec/etc/shared/rootkit_files.txt</rootkit_files>
    <rootkit_trojans>/var/ossec/etc/shared/rootkit_trojans.txt</rootkit_trojans>

    <system_audit>/var/ossec/etc/shared/system_audit_rcl.txt</system_audit>
    <system_audit>/var/ossec/etc/shared/system_audit_ssh.txt</system_audit>

    <skip_nfs>yes</skip_nfs>
  </rootcheck>

  <wodle name="open-scap">
    <disabled>yes</disabled>
    <timeout>1800</timeout>
    <interval>1d</interval>
    <scan-on-start>yes</scan-on-start>

    <content type="xccdf" path="ssg-debian-8-ds.xml">
      <profile>xccdf_org.ssgproject.content_profile_common</profile>
    </content>
    <content type="oval" path="cve-debian-oval.xml"/>
  </wodle>

  <wodle name="syscollector">
    <disabled>no</disabled>
    <interval>1h</interval>
    <scan_on_start>yes</scan_on_start>
    <hardware>yes</hardware>
    <os>yes</os>
    <network>yes</network>

    <!-- Database synchronization settings -->
    <synchronization>
      <max_eps>10</max_eps>
    </synchronization>
  </wodle>

  <!-- File integrity monitoring -->
  <syscheck>
    <disabled>no</disabled>

    <!-- Frequency that syscheck is executed default every 12 hours -->
    <frequency>43200</frequency>

    <scan_on_start>yes</scan_on_start>

    <!-- Generate alert when new file detected -->
    <alert_new_files>yes</alert_new_files>

    <!-- Don't ignore files that change more than 3 times -->
    <auto_ignore>no</auto_ignore>

    <!-- Directories to check  (perform all possible verifications) -->
    <directories>/etc,/usr/bin,/usr/sbin</directories>
    <directories>/bin,/sbin,/boot</directories>

    <!-- Files/directories to ignore -->
    <ignore>/etc/mtab</ignore>
    <ignore>/etc/hosts.deny</ignore>
    <ignore>/etc/mail/statistics</ignore>
    <ignore>/etc/random-seed</ignore>
    <ignore>/etc/random.seed</ignore>
    <ignore>/etc/adjtime</ignore>
    <ignore>/etc/httpd/logs</ignore>
    <ignore>/etc/utmpx</ignore>
    <ignore>/etc/wtmpx</ignore>
    <ignore>/etc/cups/certs</ignore>
    <ignore>/etc/dumpdates</ignore>
    <ignore>/etc/svc/volatile</ignore>
    <ignore>/sys/kernel/security</ignore>
    <ignore>/sys/kernel/debug</ignore>

    <!-- File types to ignore -->
    <ignore type="sregex">.log$|.swp$</ignore>

    <!-- Check the file, but never compute the diff -->
    <nodiff>/etc/ssl/private.key</nodiff>

    <skip_nfs>yes</skip_nfs>
    <skip_dev>yes</skip_dev>
    <skip_proc>yes</skip_proc>
    <skip_sys>yes</skip_sys>

    <!-- Nice value for Syscheck process -->
    <process_priority>10</process_priority>

    <!-- Maximum output throughput -->
    <max_eps>50</max_eps>

    <!-- Database synchronization settings -->
    <synchronization>
      <enabled>yes</enabled>
      <interval>5m</interval>
      <max_eps>10</max_eps>
    </synchronization>
  </syscheck>

  <!-- Active response -->
  <global>
    <white_list>127.0.0.1</white_list>
    <white_list>^localhost.localdomain$</white_list>
    <white_list>10.0.0.2</white_list>
  </global>

  <command>
    <name>disable-account</name>
    <executable>disable-account</executable>
    <timeout_allowed>yes</timeout_allowed>
  </command>

  <command>
    <name>restart-wazuh</name>
    <executable>restart-wazuh</executable>
  </command>

  <command>
    <name>firewall-drop</name>
    <executable>firewall-drop</executable>
    <timeout_allowed>yes</timeout_allowed>
  </command>

  <command>
    <name>host-deny</name>
    <executable>host-deny</executable>
    <timeout_allowed>yes</timeout_allowed>
  </command>

  <command>
    <name>route-null</name>
    <executable>route-null</executable>
    <timeout_allowed>yes</timeout_allowed>
  </command>

  <command>
    <name>win_route-null</name>
    <executable>route-null.exe</executable>
    <timeout_allowed>yes</timeout_allowed>
  </command>

  <!--
  <active-response>
    active-response options here
  </active-response>
  -->

  <!-- Log analysis -->
  <localfile>
    <log_format>syslog</log_format>
    <location>/var/ossec/logs/active-responses.log</location>
  </localfile>

  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/messages</location>
  </localfile>

  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/auth.log</location>
  </localfile>

  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/userlog</location>
  </localfile>

  <localfile>
    <log_format>command</log_format>
    <command>df -P</command>
    <frequency>360</frequency>
  </localfile>

  <localfile>
    <log_format>full_command</log_format>
    <command>(netstat -n -f inet && netstat -n -f inet) | grep -e "udp" -e "tcp" | sed 's/\([[:alnum:]]*\)\ *[[:digit:]]*\ *[[:digit:]]*\ *\([[:digit:]\.]*\)\.\([[:digit:]]*\)\ *\([[:digit:]\.]*\).*/\1 \2 == \3 == \4/' | sort -k4 -g | sed 's/ == \(.*\) ==/.\1/'</command>
    <frequency>360</frequency>
  </localfile>

  <localfile>
    <log_format>full_command</log_format>
    <command>last -n 5</command>
    <frequency>360</frequency>
  </localfile>

  <ruleset>
    <!-- Default ruleset -->
    <decoder_dir>ruleset/decoders</decoder_dir>
    <rule_dir>ruleset/rules</rule_dir>
    <rule_exclude>0215-policy_rules.xml</rule_exclude>
    <list>etc/lists/audit-keys</list>
    <list>etc/lists/malicious-ioc/malware-hashes</list>
    <list>etc/lists/malicious-ioc/malicious-ip</list>
    <list>etc/lists/malicious-ioc/malicious-domains</list>

    <!-- User-defined ruleset -->
    <decoder_dir>etc/decoders</decoder_dir>
    <rule_dir>etc/rules</rule_dir>
  </ruleset>

  <!-- Configuration for wazuh-authd -->
  <auth>
    <disabled>no</disabled>
    <port>1515</port>
    <use_source_ip>no</use_source_ip>
    <purge>yes</purge>
    <use_password>yes</use_password>
    <ciphers>HIGH:!ADH:!EXP:!MD5:!RC4:!3DES:!CAMELLIA:@STRENGTH</ciphers>
    <!-- <ssl_agent_ca></ssl_agent_ca> -->
    <ssl_verify_host>no</ssl_verify_host>
    <ssl_manager_cert>etc/sslmanager.cert</ssl_manager_cert>
    <ssl_manager_key>etc/sslmanager.key</ssl_manager_key>
    <ssl_auto_negotiate>no</ssl_auto_negotiate>
  </auth>

  <cluster>
    <name>wazuh</name>
    <node_name>indexer1</node_name>
    <node_type>master</node_type>
    <key></key>
    <port>1516</port>
    <bind_addr>0.0.0.0</bind_addr>
    <nodes>
        <node>NODE_IP</node>
    </nodes>
    <hidden>no</hidden>
    <disabled>yes</disabled>
  </cluster>
</ossec_config>
```

**user-files/entrypoint-scripts/001-fix-permissions.sh**:

```sh
#!/bin/sh

chmod 770 /var/ossec/etc
chown wazuh:wazuh /var/ossec/etc
chmod 640 /var/ossec/etc/authd.pass
chown root:wazuh /var/ossec/etc/authd.pass
chmod 660 /var/ossec/etc/ossec.conf
chown root:wazuh /var/ossec/etc/ossec.conf
```

**Console**:

```console
# tree /var/appjail-volumes/wazuh/indexer-connector-certs/
/var/appjail-volumes/wazuh/indexer-connector-certs/
├── node-1-key.pem
├── node-1.pem
└── root-ca.pem

1 directory, 3 files
# tree user-files/
user-files/
├── entrypoint-scripts
│   └── 001-fix-permissions.sh
├── usr
│   └── local
│       └── etc
│           └── pkg
│               └── repos
│                   └── Latest.conf
└── wazuh-config-mount
    └── etc
        ├── authd.pass
        └── ossec.conf

9 directories, 4 files
# appjail-director up
Starting Director (project:wazuh-manager) ...
Creating wazuh-manager (0d1967ad5d) ... Done.
Creating beats (08496597d0) ... Done.
Finished: wazuh-manager
```

### Upgrading using appjail-director

```sh
appjail-director down -d && appjail-director up
```

### Environment

* `HOSTNAME` (optional): Some environment variables and operations use this value. When it is not defined, the value returned by `hostname(1)` will be used.
* `WAZUH_NODE_NAME` (default: `${HOSTNAME}`): `<cluster><node_name></node_name></cluster>`can be changed using this environment variable which by default use the value of `HOSTNAME`. See also: https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/cluster.html#node-name
* `WAZUH_INDEXER_HOSTS` (optional): Unlike what the Wazuh team implemented in Docker, where hosts are separated by commas, in this case they are separated by spaces. See also: https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/indexer.html#hosts
* `WAZUH_NODE_TYPE` (optional): `<cluster><node_type></node_type></cluster>` can be changed using this environment variable which, when isn't set to `worker`, it defaults to `master`. See also: https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/cluster.html#node-type
* `WAZUH_CLUSTER_KEY` (optional): `<cluster><key></key></cluster>` can be changed using this environment variable. See also: https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/cluster.html#key
* `WAZUH_CLUSTER_BIND_ADDR` (optional): `<cluster><bind_addr></bind_addr></cluster>` can be changed using this environment variable. See also: https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/cluster.html#bind-addr
* `WAZUH_CLUSTER_NODES` (optional): A list of cluster nodes can be defined using this environment variable, a space-separated list. See also: https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/cluster.html#nodes
* `API_USERNAME` (optional): `API_USERNAME` and `API_PASSWORD`, when defined, credentials for Wazuh's API are created and the [create_user.py](https://github.com/wazuh/wazuh-docker/blob/main/build-docker-images/wazuh-manager/config/create_user.py) is executed.
* `API_PASSWORD` (optional)
* `INDEXER_PASSWORD` (optional): `INDEXER_PASSWORD`, when defined, configures indexer's credentials. `INDEXER_USERNAME` can be defined, too.
* `INDEXER_USERNAME` (optional)

### Special Mount Points

* `/var/ossec/etc/sslmanager.key`: This file must exist, or the script will create both the key and the certificate, which are not recreated when the jail is recreated, as they must exist on the volume.
* `/wazuh-config-mount/`: When mounted, the files are copied as-is to `/var/ossec`.
* `/wazuh-migration/`: When exists and have all the necessary files, a migration can be accomplished. See the `wazuh_migration` function of the [script](scripts/init.sh) for details.
* `/entrypoint-scripts/`: Can contain scripts that are executed in lexicographical order using `/bin/sh`.

### Exposed Ports

The following ports are used by the wazuh manager and can be exposed using the `expose` option of `appjail-quick(1)`. Some services may or may not be available, depending on your configuration file.

| Port      | Description                                                                                    |
| --------- | ---------------------------------------------------------------------------------------------- |
| 1514/TCP  | Agent connection service. Agents send security data to the manager for analysis.               |
| 1514/UDP  | Agent connection service. Agents send security data to the manager for analysis (**default**). |
| 1515/TCP  | Agent enrollment service. Used for agents to register with the manager.                        |
| 514/UDP   | Syslog collector for receiving logs from network devices and agentless monitoring.             |
| 514/TCP   | Syslog collector for receiving logs from network devices and agentless monitoring.             |
| 55000/TCP | Wazuh server RESTful API. Used by the Wazuh dashboard to fetch configuration and agent status. |
| 1516/TCP  | Wazuh cluster daemon for communication between server nodes in a multi-node setup.             |

### Beats

Filebeat is needed to ship alerts and archived events to logstash (and then it will ship those to OpenSearch), so this repository includes a Makejail for deploying beats in a companion jail alongside the manager.

#### Arguments

* `logstash_addr` (optional): Logstash address to connect to.
* `logstash_port` (default: `5044`): Logstash port to connect to.
* `filebeat_conf` (default: `files/filebeat.yml`): Filebeat configuration file.

## Notes

1. The ideas present in the [Docker image of Wazuh](https://github.com/wazuh/wazuh-docker) are taken into account for users who are familiar with it.
2. `/etc/localtime` file of the jail is copied to `/var/ossec/etc/localtime`, so it should exist.
3. If you have `<node_name>to_be_replaced_by_hostname</node_name>` in your `ossec.conf` configuration file, the value of this setting can be changed with the value of `HOSTNAME`. See also: https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/cluster.html#node-name
4. The owner and group of `/var/ossec/queue/rids` and `/var/ossec/etc/lists` are changed to `wazuh:wazuh` each time Makejail is run.
