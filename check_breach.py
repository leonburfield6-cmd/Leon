#!/usr/bin/env python3
"""Vérifie si une adresse e-mail apparaît dans une fuite de données connue.

Utilise l'API « Have I Been Pwned » (https://haveibeenpwned.com).
L'API nécessite une clé (payante) à placer dans la variable d'environnement
HIBP_API_KEY.

Usage :
    export HIBP_API_KEY="votre-cle"
    python3 check_breach.py votre.adresse@example.com
"""

import os
import sys
import json
import urllib.parse
import urllib.request


def check_email(email: str, api_key: str) -> list:
    """Retourne la liste des fuites où l'adresse apparaît (vide si aucune)."""
    url = (
        "https://haveibeenpwned.com/api/v3/breachedaccount/"
        + urllib.parse.quote(email)
        + "?truncateResponse=false"
    )
    req = urllib.request.Request(
        url,
        headers={
            "hibp-api-key": api_key,
            "user-agent": "leon-breach-check",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as err:
        if err.code == 404:
            # 404 = aucune fuite trouvée pour cette adresse.
            return []
        raise


def main() -> int:
    if len(sys.argv) != 2:
        print("Usage : python3 check_breach.py adresse@example.com", file=sys.stderr)
        return 2

    email = sys.argv[1]
    api_key = os.environ.get("HIBP_API_KEY")
    if not api_key:
        print(
            "Erreur : définissez la variable d'environnement HIBP_API_KEY.\n"
            "Clé disponible sur https://haveibeenpwned.com/API/Key",
            file=sys.stderr,
        )
        return 1

    breaches = check_email(email, api_key)
    if not breaches:
        print(f"Bonne nouvelle : aucune fuite connue pour {email}.")
        return 0

    print(f"Attention : {email} apparaît dans {len(breaches)} fuite(s) :\n")
    for b in breaches:
        name = b.get("Title", b.get("Name", "?"))
        date = b.get("BreachDate", "?")
        data = ", ".join(b.get("DataClasses", []))
        print(f"  - {name} ({date})")
        if data:
            print(f"      Données exposées : {data}")
    print(
        "\nConseils : changez les mots de passe concernés, n'utilisez pas "
        "le même mot de passe partout, et activez la double authentification."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
