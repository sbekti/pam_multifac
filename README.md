# pam_multifac

## What
Provides a 2-factor validation with either Yubico OTP or Duo push.

## Compiling
```
cargo build --release
```

## Setup
Install the module (this is for Debian-based distros):
```
cp target/release/libpam_multifac.so /lib/x86_64-linux-gnu/security/pam_multifac.so
```

Adjust the config file:
```
# /etc/pam_multifac.toml

[duo]
integration_key = ""
secret_key = ""
api_hostname = "api-xxxxxxxx.duosecurity.com"

[ldap]
url = "ldap://127.0.0.1:389"
bind_dn = "cn=readonly,dc=example,dc=com"
bind_pw = "changeme"
search_base = "dc=example,dc=com"
search_filter = "(&(objectClass=posixAccount)(cn={{username}}))"
search_attr = "yubiKeyId"

[yubico]
client_id = ""
api_key = ""
```

Setup PAM config:
```
# /etc/pam.d/common-auth

# here are the per-package modules (the "Primary" block)
auth    [success=3 default=ignore]      pam_unix.so nullok_secure
auth    required                        pam_ldap.so use_first_pass
auth    [success=1 default=ignore]      pam_multifac.so
# here's the fallback if no module succeeds
auth    requisite                       pam_deny.so
# prime the stack with a positive return value if there isn't one already;
# this avoids us returning an error just because nothing sets a success code
# since the modules above will each just jump around
auth    required                        pam_permit.so
# and here are more per-package modules (the "Additional" block)
# end of pam-auth-update config
```

Setup sshd config:
```
# Change to yes to enable challenge-response passwords (beware issues with
# some PAM modules and threads)
ChallengeResponseAuthentication yes
```
