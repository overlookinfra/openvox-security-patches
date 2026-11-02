#!/bin/bash

#  Copyright 2026 Overlook InfraTech
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

# This script applies a patch to OpenVox Server JAR file that swaps
# flawed hostname checking logic for a variant that properly handles
# exact and wildcard matching.
#
# Compatible with openvox-server 8.8.0 and newer.
# Likely compatible with older versions of puppetserver.
#
# When reviewing the logic of this script: start at the end and read
# towards the beginning of the file.

# === Global Variables ===

readonly VERSION='v2026.11.03'
readonly VULN_ID='GHSA-q4hm-33rc-572g'
# Use zip instead of jar to minuplate the JAR file as it is a smaller package
# to install and also does not trip over classfile versioning.
readonly -a REQUIRED_CMDS=(patch unzip zip)

declare NOOP=1 # false by default
declare DEBUG=1
declare BACKUP_DIR="/var/lib/openvox-security-patches/${VULN_ID}"
declare PATCH_TARGET="/opt/puppetlabs/server/apps/puppetserver/puppet-server-release.jar"
declare WORK_DIR


# === Helper Functions ===

#######################################
# Print help message describing script usage and options.
# Globals:
#   None
# Arguments:
#   None
# Returns:
#   0
#######################################
print_help() {
  cat <<EOF
Usage: ${0##*/} [OPTIONS]

Apply patches to remediate ${VULN_ID}.

Options:
  -d          Enable debug mode (set -x).
  -n          No-op mode. Show what would be done without making changes.
  -t FILE     Set patch target (default: ${PATCH_TARGET}).

  -h          Print this help message and exit.
EOF
}

#######################################
# Parse user flags using getopts.
# Globals:
#   NOOP       - set to 0 if -n is used
# Arguments:
#   Script arguments ($@), passed through from main.
# Returns:
#   0 on success, 1 on invalid option or missing argument.
#######################################
parse_options() {
  local OPTIND OPTARG opt
  while getopts ':dhnt:' opt; do
    case "${opt}" in
      d)
        DEBUG=0
        set -x
        ;;
      h)
        print_help
        exit 0
        ;;
      n)
        NOOP=0
        ;;
      t)
        PATCH_TARGET="${OPTARG}"
        ;;
      :)
        printf 'Error: -%s requires an argument.\n' "${OPTARG}" >&2
        print_help >&2
        exit 1
        ;;
      *)
        printf 'Error: Unknown option: -%s\n' "${OPTARG}" >&2
        print_help >&2
        exit 1
        ;;
    esac
  done
}

#######################################
# Check if a program is available on the PATH
# Globals:
#   None
# Arguments:
#   bin - binary name to search for
# Returns:
#   0 on success, 1 if program cannot be found
#######################################
find_command() {
  local bin="${1:?A command name must be passed to this function.}"

  printf "Checking \$PATH for executable: %s\n" "${bin}"

  # Run in subshell with POSIX mode enabled to ensure only executable
  # files satisfy the test.
  if (set -o posix; command -v "${bin}" >/dev/null 2>&1); then
    return 0
  else
    printf "ERROR: Could not find %s in: %s\n" "${bin}" "${PATH}" >&2
    return 1
  fi
}

#######################################
# Assert all required commands are available on the PATH
# Globals:
#   REQUIRED_CMDS - Array of required command names
# Arguments:
#   None
# Returns:
#   0 on success, 1 if a program cannot be found
#######################################
assert_required_commands() {
  for cmd in "${REQUIRED_CMDS[@]}"; do
    find_command "${cmd}" || return 1
  done

  return 0
}

#######################################
# Assert patch target exists and the user running this script has permissions
# to modify it.
# Globals:
#   PATCH_TARGET - Target file for patching
# Arguments:
#   None
# Returns:
#   0 on success, 1 if permissions are missing
#######################################
assert_patch_target_permissions() {
  printf "\nChecking permissions on patch target:\n\t%s\n" "${PATCH_TARGET}"

  if [[ ! -r $PATCH_TARGET ]]; then
    printf "ERROR: Target file does not exist or is not readable: %s\n" "${PATCH_TARGET}" >&2
    return 1
  fi

  if [[ ! -w $PATCH_TARGET ]]; then
    printf "ERROR: Target file exists, but is not writable: %s\n" "${PATCH_TARGET}" >&2
    return 1
  fi

  if [[ ! -w $(dirname "${PATCH_TARGET}") ]]; then
    printf "ERROR: Directory containing target file is not writable: %s\n" "$(dirname "${PATCH_TARGET}")" >&2
    return 1
  fi
}

#######################################
# Create backup of patch target
# Globals:
#   PATCH_TARGET - Target file for patching
#   BACKUP_DIR   - Directory in which to store backups
# Arguments:
#   None
# Returns:
#   0 on success, 1 if backup cannot be created
#######################################
backup_patch_target() {
  local backup_file
  backup_file="${BACKUP_DIR}/$(basename "${PATCH_TARGET}").bak.$$.$(date +%s)"

  if [[ $NOOP -eq 0 ]]; then
    printf "\n(noop) Copying patch target:\n\t%s\n       To backup file:\n\t%s\n" "${PATCH_TARGET}" "${backup_file}"
    return 0
  else
    printf "\n    ** Copying patch target:\n\t%s\n       To backup file:\n\t%s\n" "${PATCH_TARGET}" "${backup_file}"
  fi

  mkdir -p "$(dirname "${backup_file}")" || {
    printf "ERROR: Could not create backup directory: %s\n" "$(dirname "${backup_file}")" >&2
    return 1
  }

  cp --archive --dereference "${PATCH_TARGET}" "${backup_file}" || {
    printf "ERROR: Could not create backup: cp %s %s\n" "${PATCH_TARGET}" "${backup_file}" >&2
    return 1
  }
}

#######################################
# Clean up working directory
# Globals:
#   WORK_DIR - Working directory for patching
# Arguments:
#   None
# Returns:
#   0
#######################################
cleanup_work_dir() {
  if [[ -n $WORK_DIR ]]; then
    printf "\n    ** Cleaning up working directory:\n\t%s\n" "${WORK_DIR}"

    find "${WORK_DIR}" -delete
  fi
}


# === Main Functions ===

#######################################
# Setup working directory and report whether patch can be applied.
# Globals:
#   PATCH_TARGET - Target file for patching
#   WORK_DIR - Working directory for patching
# Arguments:
#   None
# Returns:
#   0 on success, 1 if errors occur, 2 if patch already applied.
#######################################
setup_patch() {
  local jar_file

  jar_file="$(basename "${PATCH_TARGET}")"
  WORK_DIR="$(dirname "${PATCH_TARGET}")/.openvox-patching.tmp.$$.$(date +%s)"

  printf "\n    ** Creating working directory:\n\t%s\n" "${WORK_DIR}"

  mkdir -p "${WORK_DIR}" || {
    printf "ERROR: Could not create working directory: %s\n" "${WORK_DIR}" >&2
    return 1
  }

  if [[ $DEBUG -ne 0 ]]; then
    trap cleanup_work_dir EXIT
  fi

  # Use the archive option to preserve file mode, permissions, and attributes
  # such as SELinux context.
  cp --archive "${PATCH_TARGET}" "${WORK_DIR}" || {
    printf "ERROR: Could not copy patch target into working directory.\n" >&2
    return 1
  }

  printf "\n    ** Extracting files from working copy of JAR:\n\t%s\n" "puppetlabs/trapperkeeper/authorization/acl.clj"
  (cd "${WORK_DIR}" && unzip -q -o "${jar_file}" puppetlabs/trapperkeeper/authorization/acl.clj) || {
    printf "ERROR: Could not extract source files from JAR.\n" >&2
    return 1
  }

  printf "\n    ** Checking if patch already applied.\n"
  (cd "${WORK_DIR}" && printf '%s\n' "${PATCH}" | patch -p0 --dry-run --force --reverse --fuzz=0 --ignore-whitespace >/dev/null 2>&1) && {
    printf "       NOTE: Patch already applied!\n"
    return 2
  }

  return 0
}

#######################################
# Apply patches. Sets up an isolated workspace, creates copies of target files,
# applies patches, then moves the result into place.
# Globals:
#   PATCH_TARGET - Target file for patching
# Arguments:
#   None
# Returns:
#   0 on success, 1 if errors occur during patching.
#######################################
apply_patch() {
  local jar_file

  jar_file="$(basename "${PATCH_TARGET}")"

  if [[ $NOOP -eq 0 ]]; then
    printf "\n(noop) Applying patch to working directory.\n"
  else
    printf "\n    ** Applying patch to working directory.\n"

    (cd "${WORK_DIR}" && printf '%s\n' "${PATCH}" | patch -p0 --batch --forward --fuzz=0 --ignore-whitespace) || {
      printf "ERROR: Patch command was not successful.\n" >&2
      return 1
    }
  fi

  if [[ $NOOP -eq 0 ]]; then
    printf "\n(noop) Updating working copy of JAR with patched files:\n\t%s\n" "puppetlabs/trapperkeeper/authorization/acl.clj"
  else
    printf "\n    ** Updating working copy of JAR with patched files:\n\t%s\n" "puppetlabs/trapperkeeper/authorization/acl.clj"
    (cd "${WORK_DIR}" && zip -X "${jar_file}" puppetlabs/trapperkeeper/authorization/acl.clj) || {
      printf "ERROR: Could not update working copy of JAR.\n" >&2
      return 1
    }
  fi

  if [[ $NOOP -eq 0 ]]; then
    printf "\n(noop) Restoring file mode, ownership, and extended attributes to updated JAR.\n"
  else
    printf "\n    ** Restoring file mode, ownership, and extended attributes to updated JAR.\n"
    cp --attributes-only --preserve=mode,ownership,xattr "${PATCH_TARGET}" "${WORK_DIR}/${jar_file}" || {
      printf "ERROR: Failed to copy file attributes to updated JAR.\n" >&2
      return 1
    }
  fi

  if [[ $NOOP -eq 0 ]]; then
    printf "\n(noop) Moving updated JAR into place.\n"
  else
    printf "\n    ** Moving updated JAR into place.\n"

    mv "${WORK_DIR}/${jar_file}" "${PATCH_TARGET}" || {
      printf "ERROR: Could not overwrite patch target: %s\n" "${PATCH_TARGET}" >&2
      return 1
    }
  fi

  if [[ $NOOP -eq 0 ]]; then
    printf "\n(noop) Re-starting the puppetserver service.\n"
  else
    printf "\n    ** Re-starting the puppetserver service.\n"

    systemctl try-restart puppetserver.service || {
      printf "ERROR: SystemD restart of puppetserver.service was unsuccessful.\nEnsure the service is re-started so that patched code is loaded.\n" >&2
      return 1
    }
  fi
}


#######################################
# Main entry point for the patch script.
# Globals:
#   None
# Arguments:
#   Script arguments ($@).
# Returns:
#   0
#######################################
main() {
  parse_options "$@"

  printf '%s %s\n\n' "${0##*/}" "${VERSION}" >&2

  assert_required_commands || {
    printf "\nERROR: One or more executables required by this script could not be found on the \$PATH.\n" >&2
    return 1
  }
  assert_patch_target_permissions || {
    printf "\nERROR: One or more required file permissions is not available to the user running this script.\n" >&2
    return 1
  }

  setup_patch
  case $? in
    0)
      ;;
    2)
      printf "\nPatch already applied. Nothing to do.\n"
      return 0
      ;;
    *)
      printf "\nERROR: Patch cannot be applied to this installation.\n" >&2
      return 1
      ;;
  esac

  backup_patch_target || {
    printf "\nERROR: Could not create backup of patch target before modification.\n" >&2
    return 1
  }

  apply_patch || {
    printf "\nERROR: Patch was not successfully applied.\n" >&2
    return 1
  }
}

# Patch to apply. Located here at the end to make review easy and to contain
# any interference with syntax highlighting.
PATCH=$(cat <<'EOF'
--- puppetlabs/trapperkeeper/authorization/acl.clj
+++ puppetlabs/trapperkeeper/authorization/acl.clj
@@ -79,7 +79,7 @@
 (def ACE
   "An authorization entry matching a network or a domain"
   {:auth-type AuthType
-   :match (schema/enum :string :regex :backreference :extensions :rbac-permission)
+   :match (schema/enum :string :wildcard :regex :backreference :extensions :rbac-permission)
    :value ACEValue})
 
 (def ACL
@@ -166,7 +166,7 @@
     (re-matches #"^\*(\.(\w[-\w]*)){1,}$" certname)
     (let [host_sans_star (vec (drop-last (split-domain certname)))]
       {:auth-type auth-type
-       :match :string
+       :match :wildcard
        :value host_sans_star})
 
     ; backreference
@@ -199,9 +199,10 @@
   [{:keys [value match]} :- ACE
    to-match :- schema/Str]
   (let [match-split-domain (split-domain to-match)]
-    (if (= :regex match)
-      (boolean (re-find (re-pattern value) to-match))
-      (every? (fn [[a b]] (= a b)) (map vector value match-split-domain)))))
+    (case match
+      :regex (boolean (re-find (re-pattern value) to-match))
+      :wildcard (= value (take (count value) match-split-domain))
+      (= value match-split-domain))))
 
 (schema/defn ^:private substitute-backreference :- schema/Str
   "substiture $1, $2... by the same index in the captures vector"
EOF
)

# Entrypoint for when the script is executed.
# A "return" statement at top-level only succeeds when the file is loaded by
# "source" or ".". This test allows for loading the script into an interactive
# terminal session in order to exercise the various functions.
if ! (return 0 2>/dev/null); then
  main "$@"
  exit $?
fi
