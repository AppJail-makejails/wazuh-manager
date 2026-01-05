#!/bin/sh
# Wazuh App Copyright (C) 2017, Wazuh Inc. (License GPLv2)

. /scripts/lib.subr

if [ -z "${HOSTNAME}" ]; then
    HOSTNAME=`hostname` || exit $?
fi

sync_localtime()
{
    exec_cmd_stdout "cp /etc/localtime /var/ossec/etc/localtime"
}

create_ossec_key_cert()
{
    if [ ! -e /var/ossec/etc/sslmanager.key ]; then
        info "Creating wazuh-authd key and cert"
        exec_cmd "openssl genrsa -out /var/ossec/etc/sslmanager.key 4096"
        exec_cmd "openssl req -new -x509 -key /var/ossec/etc/sslmanager.key -out /var/ossec/etc/sslmanager.cert -days 3650 -subj /CN=${HOSTNAME}/"
    fi
}

mount_files()
{
    if [ -e "/wazuh-config-mount" ]; then
        info "Identified Wazuh configuration files to mount..."
        exec_cmd_stdout "cp -va /wazuh-config-mount/ /var/ossec"
    else
        info "No Wazuh configuration files to mount..."
    fi
}

set_custom_hostname()
{
    gsed -i 's/<node_name>to_be_replaced_by_hostname<\/node_name>/<node_name>'"${HOSTNAME}"'<\/node_name>/g' /var/ossec/etc/ossec.conf
}

configure_ossec_conf()
{
    OSSEC_CONF="/var/ossec/etc/ossec.conf"

    # --------------------------
    # Defaults based on OSSEC_CONF
    # --------------------------
    if [ -z "$WAZUH_CLUSTER_KEY" ]; then
        WAZUH_CLUSTER_KEY=$(gsed -n '/<cluster>/,/<\/cluster>/s/.*<key>\(.*\)<\/key>.*/\1/p' "$OSSEC_CONF" | head -n1)
    fi

    # Node type logic
    if [ "$WAZUH_NODE_TYPE" != "worker" ]; then
        WAZUH_NODE_TYPE="master"
    fi

    # Default node name -> HOSTNAME if not defined
    WAZUH_NODE_NAME="${WAZUH_NODE_NAME:-$HOSTNAME}"

    # --------------------------
    # Replace Indexer Hosts
    # --------------------------
    if [ -n "$WAZUH_INDEXER_HOSTS" ]; then
        TMP_HOSTS=$(mktemp)
        {
            echo "    <hosts>"
            for NODE in ${WAZUH_INDEXER_HOSTS}; do
                IP="${NODE%:*}"
                PORT="${NODE#*:}"
                echo "      <host>https://$IP:$PORT</host>"
            done
            echo "    </hosts>"
        } > "$TMP_HOSTS"
        gsed -i -e '/<indexer>/,/<\/indexer>/{ /<hosts>/,/<\/hosts>/{ /<hosts>/r '"$TMP_HOSTS" -e 'd }}' "$OSSEC_CONF"
        rm -f "$TMP_HOSTS"
    fi

    # --------------------------
    # Cluster: node_name
    # --------------------------
    gsed -i "/<cluster>/,/<\/cluster>/ s|<node_name>.*</node_name>|<node_name>$WAZUH_NODE_NAME</node_name>|" "$OSSEC_CONF"

    # --------------------------
    # Cluster: node_type
    # --------------------------
    gsed -i "/<cluster>/,/<\/cluster>/ s|<node_type>.*</node_type>|<node_type>$WAZUH_NODE_TYPE</node_type>|" "$OSSEC_CONF"

    # --------------------------
    # Cluster: key
    # --------------------------
    gsed -i "/<cluster>/,/<\/cluster>/ s|<key>.*</key>|<key>$WAZUH_CLUSTER_KEY</key>|" "$OSSEC_CONF"

    # --------------------------
    # Cluster: bind_addr
    # --------------------------
    gsed -i "/<cluster>/,/<\/cluster>/ s|<bind_addr>.*</bind_addr>|<bind_addr>$WAZUH_CLUSTER_BIND_ADDR</bind_addr>|" "$OSSEC_CONF"

    # --------------------------
    # Cluster: nodes list
    # --------------------------
    if [ -n "$WAZUH_CLUSTER_NODES" ]; then
        TMP_NODES=$(mktemp)
        {
            echo "    <nodes>"
            for N in $WAZUH_CLUSTER_NODES; do
                echo "        <node>$N</node>"
            done
            echo "    </nodes>"
        } > "$TMP_NODES"
        gsed -i -e '/<cluster>/,/<\/cluster>/{ /<nodes>/,/<\/nodes>/{ /<nodes>/r '"$TMP_NODES" -e 'd }}' "$OSSEC_CONF"
        rm -f "$TMP_NODES"
    fi

    echo "Wazuh manager config modified successfully."
}

configure_permissions()
{
    chown -R wazuh:wazuh /var/ossec/queue/rids
    chown -R wazuh:wazuh /var/ossec/etc/lists
}

wazuh_migration()
{
    if [ -d "/wazuh-migration" ]; then
        if [ ! -e /wazuh-migration/.migration-completed ]; then
            if [ ! -e /wazuh-migration/global.db ]; then
                warn "The volume mounted on /wazuh-migration does not contain all the correct files."
                return
            fi

            cp -f /wazuh-migration/data/etc/ossec.conf /var/ossec/etc/ossec.conf
            chown root:wazuh /var/ossec/etc/ossec.conf
            chmod 640 /var/ossec/etc/ossec.conf

            cp -f /wazuh-migration/data/etc/client.keys /var/ossec/etc/client.keys
            chown wazuh:wazuh /var/ossec/etc/client.keys
            chmod 640 /var/ossec/etc/client.keys

            cp -f /wazuh-migration/data/etc/sslmanager.cert /var/ossec/etc/sslmanager.cert
            cp -f /wazuh-migration/data/etc/sslmanager.key /var/ossec/etc/sslmanager.key
            chown root:root /var/ossec/etc/sslmanager.cert /var/ossec/etc/sslmanager.key
            chmod 640 /var/ossec/etc/sslmanager.cert /var/ossec/etc/sslmanager.key

            cp -f /wazuh-migration/data/etc/shared/default/agent.conf /var/ossec/etc/shared/default/agent.conf
            chown wazuh:wazuh /var/ossec/etc/shared/default/agent.conf
            chmod 660 /var/ossec/etc/shared/default/agent.conf

            cp -f /wazuh-migration/data/etc/decoders/* /var/ossec/etc/decoders/
            chown wazuh:wazuh /var/ossec/etc/decoders/*
            chmod 660 /var/ossec/etc/decoders/*

            cp -f /wazuh-migration/data/etc/rules/* /var/ossec/etc/rules/
            chown wazuh:wazuh /var/ossec/etc/rules/*
            chmod 660 /var/ossec/etc/rules/*

            cp -f /wazuh-migration/global.db /var/ossec/queue/db/global.db
            chown wazuh:wazuh /var/ossec/queue/db/global.db
            chmod 640 /var/ossec/queue/db/global.db

            # mark volume as migrated
            touch /wazuh-migration/.migration-completed

            info "Migration completed succesfully"
        else
            warn "This volume has already been migrated. You may proceed and remove it from the mount point (/wazuh-migration)"
        fi
    fi
}

create_custom_user()
{
    if [ ! -z "$API_USERNAME" ] && [ ! -z "$API_PASSWORD" ]; then
        cat << EOF > /var/ossec/api/configuration/admin.json
{
  "username": "$API_USERNAME",
  "password": "$API_PASSWORD"
}
EOF

        # create or customize API user
        if env CRYPTOGRAPHY_OPENSSL_NO_LEGACY=1 /var/ossec/framework/python/bin/python3 /var/ossec/framework/scripts/create_user.py; then
            # remove json if exit code is 0
            rm /var/ossec/api/configuration/admin.json
        else
            err "There was an error configuring the API user"
            # terminate container to avoid unpredictable behavior
            exit 1
        fi
    fi
}

configure_vulnerability_detection()
{
    if [ -n "$INDEXER_PASSWORD" ]; then
        info "Configuring password."
        echo "$INDEXER_PASSWORD" | /var/ossec/bin/wazuh-keystore -f indexer -k password
        echo "$INDEXER_USERNAME" | /var/ossec/bin/wazuh-keystore -f indexer -k username
    fi
}

entrypoint_scripts()
{
    # It will run every .sh script located in entrypoint-scripts folder in lexicographical order
    if [ -d "/entrypoint-scripts/" ]; then
        for script in `ls /entrypoint-scripts/*.sh | sort -n`; do
            /bin/sh "$script"
        done
    fi
}

sync_localtime

create_ossec_key_cert

mount_files

set_custom_hostname

configure_ossec_conf

configure_permissions

wazuh_migration

create_custom_user

configure_vulnerability_detection

entrypoint_scripts
