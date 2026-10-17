# CertCheck — scanner de certificats SSL/TLS

Se connecte à un ou plusieurs hôtes, récupère le certificat SSL/TLS présenté et affiche les champs utiles (sujet, émetteur, validité, liste SAN...).
*Connects to one or more hosts, retrieves the SSL/TLS certificate and shows the useful fields.*

![Demo: example.com (IANA documentation domain)](docs/demo.gif)


## Usage
```
python3 certcheck.py exemple.com
python3 certcheck.py exemple.com:8443 github.com
python3 certcheck.py -t 4 exemple.com          # timeout de connexion 4 s
```

## Options
| Option | Rôle |
|---|---|
| `hosts` | Un ou plusieurs `hôte` ou `hôte:port` (port 443 par défaut) |
| `-t`, `--timeout` | Timeout de connexion en secondes (défaut 4) |
| `--no-banner` | Masquer la bannière ASCII |

Aucune dépendance externe (stdlib Python uniquement).
