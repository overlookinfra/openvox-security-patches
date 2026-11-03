OpenVox Security Patches
========================

This repository contains patches for security issues affecting OpenVox software
projects. The content is organized into two collections:

  - `patches/`: raw patch files.

  - `scripts/`: scripts that apply patches to deployed software installations.


## Patching Scripts

The patching scripts in this repository are intended for use when an
immediate-term option for hot patching security issues is required.
Regular package upgrades should always be preferred to hot patching, and
hot patching should always be followed up by a planned upgrade of the affected
packages.

The patching scripts in this repository execute the following workflow, and
abort if an error occurs at any step:

  1. Verification of required tools and filesystem access rights.
  2. Check for already applied patches.
  3. Backup of original unpatched files to: `/var/lib/openvox-security-patches/`
  4. Application of patches to copies of original files.
  5. Swap of patched copies for original files, followed by restart of affected services.

Run the scripts as `root`. Download and review a script before running it, and
do a no-op run using the `-n` flag first:

```
curl -fsSLO <script URL>
less <script>            # Do due diligence
sudo bash <script> -n    # report what would be done; skips steps 3-5
sudo bash <script>
```

Pass `-h` to see all options.

### GHSA-ffr6-rwpm-p5wq: Authenticated RCE on Puppet server via Event Deserialization

Fixes a [9.4 CVE that allows remote code execution (RCE)][GHSA-ffr6-rwpm-p5wq].
Apply to any node running a primary or compiler `openvox-server` where the
`openvox-agent` package is older than release 9.3.0 or 8.32.0. Requires the
`patch` command to be available.

https://raw.githubusercontent.com/overlookinfra/openvox-security-patches/refs/heads/main/scripts/GHSA-ffr6-rwpm-p5wq-Authenticated-RCE-on-Puppet-server-via-Event-Deserialization.sh

After patching, perform a planned upgrade of the `openvox-agent` package as soon
as possible.

[GHSA-ffr6-rwpm-p5wq]: https://github.com/OpenVoxProject/openvox/security/advisories/GHSA-ffr6-rwpm-p5wq

### GHSA-q4hm-33rc-572g: Flawed Hostname Check allows Puppet Client Impersonation

Fixes a [9.5 CVE that allows bypassing API access control rules][GHSA-q4hm-33rc-572g]
in `auth.conf` files used by `openvox-server` and `openvoxdb`. Apply to any
node running a primary or compiler `openvox-server` where the package is older
than release 9.2.0 or 8.18.0. Requires the `patch`, `unzip`, and `zip` commands
to be available.

https://raw.githubusercontent.com/overlookinfra/openvox-security-patches/refs/heads/main/scripts/GHSA-q4hm-33rc-572g-Flawed-Hostname-Check-allows-Puppet-Client-Impersonation.sh

After patching, perform a planned upgrade of the `openvox-server` package as
soon as possible.

[GHSA-q4hm-33rc-572g]: https://github.com/OpenVoxProject/trapperkeeper-authorization/security/advisories/GHSA-q4hm-33rc-572g
