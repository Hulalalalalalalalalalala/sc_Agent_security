#!/usr/bin/env bash
# Copy lab user passwords from the cluster Secret into rossoctl-backend.
# The destination path is inside that container. A same-named file on the Mac is not used.
# Values are not printed. The Secret is not stored in git.
set -euo pipefail
CTX="${CTX:-kind-agent-identity-lab}"
NS="${NS:-rossoctl-system}"
SECRET="${SECRET:-lab-user-credentials}"
export PATH="/Users/hulalala/Desktop/A/.tools/bin:${HOME}/.docker/bin:${PATH}"
if ! kubectl --context "$CTX" -n "$NS" get secret "$SECRET" >/dev/null 2>&1; then
  echo "missing_secret: ${NS}/${SECRET}" >&2
  echo "Create it without echoing the values, for example:" >&2
  echo "  kubectl --context ${CTX} -n ${NS} create secret generic ${SECRET} --from-file=lab-ny=./lab-ny.pass --from-file=lab-lon=./lab-lon.pass" >&2
  echo "Then delete the local files. Do not commit them." >&2
  exit 1
fi
BPOD="$(kubectl --context "$CTX" -n "$NS" get pod -l app.kubernetes.io/name=rossoctl-backend -o jsonpath='{.items[0].metadata.name}')"
if [ -z "$BPOD" ]; then
  echo "missing_pod: rossoctl-backend in ${NS}" >&2
  exit 1
fi
copy_one() {
  local key="$1"
  local dest="$2"
  local tmp
  tmp="$(mktemp)"
  chmod 600 "$tmp"
  if ! kubectl --context "$CTX" -n "$NS" get secret "$SECRET" -o "jsonpath={.data.${key}}" | base64 -d > "$tmp"; then
    rm -f "$tmp"
    echo "secret_key_unreadable: ${key}" >&2
    exit 1
  fi
  if [ ! -s "$tmp" ]; then
    rm -f "$tmp"
    echo "secret_key_empty: ${key}" >&2
    exit 1
  fi
  kubectl --context "$CTX" -n "$NS" exec -i "$BPOD" -c backend -- sh -c "cat > ${dest} && chmod 600 ${dest}" < "$tmp"
  rm -f "$tmp"
}
copy_one lab-ny /tmp/lab-ny.pass
copy_one lab-lon /tmp/lab-lon.pass
echo "prepared_inside_pod=${NS}/${BPOD} files=/tmp/lab-ny.pass,/tmp/lab-lon.pass mode=600"
echo "These files disappear when the rossoctl-backend Pod is recreated. Run this script again."
echo "Remove them with: kubectl --context ${CTX} -n ${NS} exec deploy/rossoctl-backend -c backend -- rm -f /tmp/lab-ny.pass /tmp/lab-lon.pass"
