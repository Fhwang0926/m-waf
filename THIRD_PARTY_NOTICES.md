# Third-party components

M-WAF does not implement a new WAF engine or attack-rule parser. The MVP packages configure and distribute existing open-source components.

| Component | Project | How it is used |
|---|---|---|
| ModSecurity v2 | [OWASP ModSecurity](https://github.com/owasp-modsecurity/ModSecurity) | Ubuntu `libapache2-mod-security2` package used by the Apache integration package |
| libmodsecurity v3 | [OWASP ModSecurity](https://github.com/owasp-modsecurity/ModSecurity) | Ubuntu `libmodsecurity3` dependency used by the Nginx integration package |
| Nginx connector | [ModSecurity-nginx](https://github.com/owasp-modsecurity/ModSecurity-nginx) | Ubuntu `libnginx-mod-http-modsecurity` package used unchanged |
| OWASP CRS | [coreruleset/coreruleset](https://github.com/coreruleset/coreruleset) | Official v4.28.0 rules copied unchanged into both integration packages |
| MariaDB | [MariaDB Server](https://github.com/MariaDB/server) | Official container image used by the Manager deployment stack |
| Go MySQL Driver | [go-sql-driver/mysql](https://github.com/go-sql-driver/mysql) | Manager's MariaDB protocol driver |

Exact versions and source hashes are recorded in `packaging/sources.lock.yaml` and in each generated bundle manifest. The CRS license is included in each module package. Distribution of a release must also preserve the license and source-offer requirements of its distro packages and container base images.
