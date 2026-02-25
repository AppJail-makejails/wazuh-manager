#!/usr/local/bin/bash

. /scripts/lib.subr
. /permanent_data.env

set -o pipefail

if [ ! -d "/data" ]; then
    info "Creating permanent data directory"
    exec_cmd_stdout "mkdir -p /data"
fi

# To avoid errors in tar(1), we need to remove non existent files.

i=0; l=
for f in ${PERMANENT_DATA[@]}; do
    if [ ! -e "${f}" ]; then
        continue
    fi

    l[((i++))]="${f}"
done
PERMANENT_DATA=("${l[@]}")
i=0; l=
for f in ${PERMANENT_DATA_EXCP[@]}; do
    if [ ! -e "${f}" ]; then
        continue
    fi

    l[((i++))]="${f}"
done
PERMANENT_DATA_EXCP=("${l[@]}")

info "Copying permanent data to volume"
tar -C / -cf - ${PERMANENT_DATA[@]} | tar -C /data --strip-components=2 -xvpkf - || exit $?

info "Updating non-permanent data in permanent data volume"
tar -C / -cf - ${PERMANENT_DATA_EXCP[@]} | tar -C /data --strip-components=2 -xvpf - || exit $?

info "Preparing nullfs mount points"
for f in ${PERMANENT_DATA[@]} ${PERMANENT_DATA_EXCP[@]}; do
    # Only nullfs to directories.
    if [ ! -d "${f}" ]; then
        continue
    fi

    exec_cmd_stdout "rm -rf ${f}"
    exec_cmd_stdout "mkdir -p ${f}"

    echo "${f#/var/ossec/}" >> /wazuh-manager-mount.lst || exit $?
done

info "Mounting nullfs mount points"
service wazuh-manager-mount enable
service wazuh-manager-mount start

info "Removing files that should be deleted"
for del_file in "${PERMANENT_DATA_DEL[@]}"; do
    if [ -e ${del_file} ]; then
        info "Removing ${del_file}"
        exec_cmd "rm -f ${del_file}"
    fi
done

warn "*DON'T UPDATE WAZUH USING pkg(8)*"
