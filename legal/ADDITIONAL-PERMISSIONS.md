# Additional permissions under GNU GPL version 3, section 7

Enclave is free software: you can redistribute it and/or modify it under the
terms of the GNU General Public License version 3 (see `LICENSE`), with the
following additional permissions granted by the copyright holders under
section 7 of that license. These permissions apply to all code in this
repository whose copyright is held by the Enclave contributors. Each
contributor grants them for their contribution by signing off under the
Developer Certificate of Origin (see `CONTRIBUTING.md`).

## 1. App-store distribution

You may convey Enclave, or a work based on it, in object code form through a
software distribution service (for example Apple's App Store or Google Play)
whose terms of service would otherwise conflict with sections 6 or 10 of the
GPL, provided that:

1. the Corresponding Source for that exact version is available to recipients
   under the plain GPLv3 (without this permission) at no charge from a
   publicly accessible location, and
2. you do not impose any further restrictions on recipients beyond those that
   the distribution service imposes by itself.

## 2. Linking with Slint under the Slint Royalty-free License 2.0

You may combine Enclave with the Slint UI toolkit when Slint is used under the
Slint Royalty-free Desktop, Mobile, and Web Applications License 2.0, and
convey the combination, provided that the attribution the Slint license
requires (the "About Slint" notice) is shown in the application's About screen.
The Enclave parts of the combination remain under the GPLv3 with these
permissions.

## 3. Platform system libraries and SDKs

You may link Enclave with the platform libraries and SDKs of the operating
systems it runs on (for example Apple frameworks, the Android SDK and Google
Play services client libraries, and Windows SDK libraries), and convey the
combination, even where those libraries are not "System Libraries" in the sense
of section 1 of the GPL.

## Scope

These permissions do not extend to third-party code included in or linked by
Enclave; such code keeps its own license. Anyone who modifies Enclave may
remove these permissions from their version, as section 7 allows.


## Third-party copyleft in App Store builds (open item)

Enclave once used `equix` and `hashx` (the Equi-X proof of work, from the Tor Project), which are LGPL-3.0-only: compatible with GPLv3, but not covered by the permissions above, since those cover only code whose copyright holders granted them. Enclave now uses its own Equihash proof of work instead (`docs/rfcs/0004-equihash-instead-of-equix.md`), so no LGPL code ships in any build. `cargo deny` (`deny-ios.toml` for the App Store build) flags any new copyleft dependency.
