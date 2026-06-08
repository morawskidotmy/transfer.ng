transfer() {
    if [ $# -eq 0 ]; then
        echo "Usage: transfer <file|directory> [file2 ...]"
        return 1
    fi

    local host="${TRANSFER_HOST:-https://transfer.morawski.my}"
    host="${host%/}"

    _transfer_urlencode_component() {
        local LC_ALL=C
        local s="$1" out="" c hex
        while [ -n "$s" ]; do
            c="${s%${s#?}}"
            case "$c" in
                [a-zA-Z0-9.~_-]) out="${out}${c}" ;;
                *)
                    hex=$(printf '%%%02X' "'$c")
                    out="${out}${hex}"
                    ;;
            esac
            s="${s#?}"
        done
        printf '%s' "$out"
    }

    _transfer_urlencode_path() {
        local p="${1#./}" out="" part
        while [ -n "$p" ]; do
            part="${p%%/*}"
            [ -n "$out" ] && out="${out}/"
            out="${out}$(_transfer_urlencode_component "$part")"
            [ "$p" = "$part" ] && break
            p="${p#*/}"
        done
        printf '%s' "$out"
    }

    _transfer_wait_batch() {
        local failed=0 pid
        for pid in "$@"; do
            wait "$pid" || failed=1
        done
        return "$failed"
    }

    local items=()
    local arg dir base f rel
    for arg in "$@"; do
        if [ -d "$arg" ]; then
            dir="${arg%/}"
            base="${dir##*/}"
            while IFS= read -r -d '' f; do
                rel="${base}/${f#"$dir"/}"
                items+=("$f" "$rel")
            done < <(find "$dir" -type f -print0)
        elif [ -f "$arg" ]; then
            items+=("$arg" "${arg##*/}")
        else
            echo "Skipping: $arg (not a file or directory)" >&2
        fi
    done

    if [ ${#items[@]} -eq 0 ]; then
        echo "No files to upload" >&2
        return 1
    fi

    local tmpdir=$(mktemp -d)
    curl --silent --show-error --fail -D "$tmpdir/headers" -o /dev/null \
        -X POST "$host/dir" || { rm -rf "$tmpdir"; echo "Failed to create directory"; return 1; }
    local dir_url=$(grep -i '^X-Url-Directory:' "$tmpdir/headers" | sed 's/^[^:]*: *//' | tr -d '\r')
    local upload_token=$(grep -i '^X-Upload-Token:' "$tmpdir/headers" | sed 's/^[^:]*: *//' | tr -d '\r')
    rm -rf "$tmpdir"
    if [ -z "$dir_url" ] || [ -z "$upload_token" ]; then
        echo "Failed to create directory"
        return 1
    fi

    local max=8 failed=0
    local pids=() url
    set -- "${items[@]}"
    while [ $# -gt 0 ]; do
        f="$1"
        rel="$2"
        shift 2
        url="${dir_url}$(_transfer_urlencode_path "$rel")"
        (
            if curl --silent --show-error --fail --globoff \
                    -H "X-Upload-Token: $upload_token" \
                    --upload-file "$f" "$url" >/dev/null; then
                echo "$url"
            else
                echo "FAILED: $f" >&2
                exit 1
            fi
        ) &
        pids+=("$!")
        if [ ${#pids[@]} -ge "$max" ]; then
            _transfer_wait_batch "${pids[@]}" || failed=1
            pids=()
        fi
    done

    if [ ${#pids[@]} -gt 0 ]; then
        _transfer_wait_batch "${pids[@]}" || failed=1
    fi

    if [ "$failed" -ne 0 ]; then
        echo "One or more uploads failed" >&2
        return 1
    fi

    echo "Directory: $dir_url"
}
