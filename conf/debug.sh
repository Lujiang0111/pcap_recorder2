#!/usr/bin/env bash
if [ -z "${BASH_VERSION:-}" ]; then
    exec bash "$0" "$@"
fi

shell_dir=$(
    cd "$(dirname "$0")" || exit
    pwd
)
shell_dir=$(realpath "${shell_dir}")

project=pcap_recorder2
lib_dir=${shell_dir}/lib

ulimit -n 65536
export LD_LIBRARY_PATH=${lib_dir}:${LD_LIBRARY_PATH}

cd "${lib_dir}" || exit
for file in ./*.so.*; do
    [ -f "${file}" ] || continue

    realname=${file#./}
    libname=${realname%%.so.*}.so
    [ -e "${libname}" ] || ln -sf "${realname}" "${libname}"
done
ldconfig -n .

cd "${shell_dir}" || exit
runlog_max_size=10000000
if [ -f runlog ]; then
    runlog_size=$(stat --format=%s runlog)
    if [ "${runlog_size}" -gt ${runlog_max_size} ]; then
        echo -e "runlog too big, restart at $(date +"%Y-%m-%d %H:%M:%S")" >runlog
    fi
fi

function TrapSigint() {
    :
}
trap TrapSigint 2

echo -e "${project}-debug start at $(date +"%Y-%m-%d %H:%M:%S")" >>runlog

cd "${shell_dir}" || exit
chmod +x ${project}
gdb --args ${project} "$@"

echo -e "${project}-debug stop at $(date +"%Y-%m-%d %H:%M:%S")" >>runlog
