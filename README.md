PAM LDAP Set Quota Linux
========================
This PAM module reads quota attribute from LDAP then changes user quota on opening session.

Requirement
-----------
- Install build essential package
- Install CMake 3.10 or higher
- Config linux authenticator to use LDAP. https://goo.gl/1eRdtW
- Install and config `quota` package on linux. https://goo.gl/Bsmwng

For Ubuntu 16.04:
- `libldap2-dev`
- `libpam0g-dev`

For Opensuse:
- `pam-devel`
- `libldap-2_X_Y`

Installation
------------
- Config and load `quota.schema` on your LDAP server.
- Add `systemQuotas` objectClass to each user entry.
- Add `quota` attribute to each user with the following value:

        Quotas (FileSystem:BlocksSoft,BlocksHard,InodesSoft,InodesHard)

    Example:

        /:100,200,300,400
  - `/` : Address of filesystem.
  - `100` : BlocksSoft.
  - `200` : BlocksHard.
  - `300` : InodesSoft.
  - `400` : InodesHard.

  Note that in order to disable `BlocksSoft`, `BlocksHard`, `BlocksHard`, `InodesHard`, you can set them (or each one) to zero (`0`).
- Change `config.h` in this library according to your LDAP server.
- Compile library:

        cd pam_ldapsetquota
        mkdir build
        cd build
        cmake ..
        make
        
- Copy `libpam_ldapsetquota.so` to `/lib/security` (create `security` folder if it doesn't exist).
- Change `security` folder (if you created it) and `libpam_ldapsetquota.so` owner to `root:root`.
- Change chmod of `security` folder (if you created it) and `libpam_ldapsetquota.so` to `755` and `644` respectively.
- Append the following line to `/etc/pam.d/common-session`

        session	optional	/lib/security/libpam_ldapsetquota.so

  - `optional` can be changed to `required` that leads to forcely cancel creating user session if any error occurred.
  - You can check log on `auth.log` (`/var/log/auth.log`).

Useful Resources
----------------
Set quota C source code:
- https://github.com/amirsafiallah/setquota

C source code to read quota.schema from ldap in linux:
- https://github.com/amirsafiallah/ldapquota

Set quota on opening user session:
- https://github.com/amirsafiallah/pam_setquota/
