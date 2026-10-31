"""
osint.py - Petite boîte à outils OSINT en Python.

À utiliser uniquement sur tes propres domaines, IP, fichiers,
ou dans un cadre autorisé (CTF, audit avec accord écrit).

Exemples :
    python osint.py domaine example.com
    python osint.py sousdomaines example.com
    python osint.py ip 8.8.8.8
    python osint.py headers https://example.com
    python osint.py exif photo.jpg
    python osint.py fuite            (vérifie un mot de passe dans les fuites)
"""

import argparse
import getpass
import hashlib
import sys

import requests

TIMEOUT = 15
UA = {"User-Agent": "Mozilla/5.0 (osint.py)"}


def titre(texte):
    print(f"\n=== {texte} ===")


# ---------------------------------------------------------------- domaine
def cmd_domaine(cible):
    import dns.resolver
    import whois

    titre(f"WHOIS : {cible}")
    try:
        w = whois.whois(cible)
        for cle in ["registrar", "creation_date", "expiration_date", "name_servers", "country"]:
            print(f"{cle:16}: {w.get(cle)}")
    except Exception as e:
        print("WHOIS indisponible :", e)

    titre("DNS")
    for type_ in ["A", "AAAA", "MX", "NS", "TXT"]:
        try:
            for r in dns.resolver.resolve(cible, type_, lifetime=TIMEOUT):
                print(f"{type_:5} {r.to_text()}")
        except Exception:
            pass


# ----------------------------------------------------------- sous-domaines
def cmd_sousdomaines(cible):
    titre(f"Sous-domaines (certificats publics crt.sh) : {cible}")
    try:
        r = requests.get(f"https://crt.sh/?q=%25.{cible}&output=json", headers=UA, timeout=60)
        r.raise_for_status()
        noms = set()
        for entree in r.json():
            for nom in entree["name_value"].split("\n"):
                nom = nom.strip().lower()
                if nom and not nom.startswith("*"):
                    noms.add(nom)
        for n in sorted(noms):
            print(" ", n)
        print(f"\nTotal : {len(noms)}")
    except Exception as e:
        print("crt.sh indisponible :", e)


# ---------------------------------------------------------------------- ip
def cmd_ip(cible):
    titre(f"Infos IP : {cible}")
    try:
        r = requests.get(f"http://ip-api.com/json/{cible}", timeout=TIMEOUT).json()
        for cle in ["query", "country", "regionName", "city", "isp", "org", "as"]:
            print(f"{cle:12}: {r.get(cle)}")
    except Exception as e:
        print("Service indisponible :", e)


# ----------------------------------------------------------------- headers
def cmd_headers(cible):
    if not cible.startswith("http"):
        cible = "https://" + cible
    titre(f"En-têtes HTTP : {cible}")
    try:
        r = requests.get(cible, headers=UA, timeout=TIMEOUT)
        print("Statut :", r.status_code)
        for k in ["Server", "X-Powered-By", "Content-Security-Policy",
                  "Strict-Transport-Security", "X-Frame-Options", "X-Content-Type-Options"]:
            print(f"{k:28}: {r.headers.get(k, '- absent')}")
    except Exception as e:
        print("Site injoignable :", e)


# -------------------------------------------------------------------- exif
def cmd_exif(chemin):
    from PIL import Image
    from PIL.ExifTags import GPSTAGS, TAGS

    titre(f"Métadonnées EXIF : {chemin}")
    try:
        donnees = Image.open(chemin).getexif()
    except Exception as e:
        print("Impossible d'ouvrir l'image :", e)
        return
    if not donnees:
        print("Aucune métadonnée EXIF.")
        return
    for tag_id, valeur in donnees.items():
        print(f"{TAGS.get(tag_id, tag_id)!s:25}: {valeur}")
    gps = donnees.get_ifd(0x8825)
    if gps:
        titre("GPS (attention : révèle le lieu de la photo)")
        for k, v in gps.items():
            print(f"{GPSTAGS.get(k, k)!s:25}: {v}")


# ------------------------------------------------------------------- fuite
def cmd_fuite(_=None):
    """Vérifie un mot de passe via Have I Been Pwned (k-anonymat :
    seuls les 5 premiers caractères du hash SHA-1 sont envoyés)."""
    mdp = getpass.getpass("Mot de passe à vérifier (non affiché) : ")
    sha1 = hashlib.sha1(mdp.encode()).hexdigest().upper()
    prefixe, suffixe = sha1[:5], sha1[5:]
    try:
        r = requests.get(f"https://api.pwnedpasswords.com/range/{prefixe}", headers=UA, timeout=TIMEOUT)
        r.raise_for_status()
    except Exception as e:
        print("Service indisponible :", e)
        return
    for ligne in r.text.splitlines():
        h, nb = ligne.split(":")
        if h == suffixe:
            print(f"⚠️  Ce mot de passe apparaît {nb} fois dans des fuites. Change-le !")
            return
    print("✅ Pas trouvé dans les fuites connues.")


COMMANDES = {
    "domaine": (cmd_domaine, "WHOIS + enregistrements DNS d'un domaine"),
    "sousdomaines": (cmd_sousdomaines, "sous-domaines via les certificats publics"),
    "ip": (cmd_ip, "géolocalisation et FAI d'une adresse IP"),
    "headers": (cmd_headers, "en-têtes de sécurité d'un site web"),
    "exif": (cmd_exif, "métadonnées d'une photo (GPS, appareil...)"),
    "fuite": (cmd_fuite, "mot de passe présent dans une fuite ?"),
}


def main():
    parser = argparse.ArgumentParser(
        description="Boîte à outils OSINT",
        epilog="\n".join(f"  {k:13} {v[1]}" for k, v in COMMANDES.items()),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("commande", choices=COMMANDES)
    parser.add_argument("cible", nargs="?", help="domaine, IP, URL ou fichier")
    args = parser.parse_args()

    if args.commande != "fuite" and not args.cible:
        parser.error(f"la commande '{args.commande}' demande une cible")

    COMMANDES[args.commande][0](args.cible)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit("\nInterrompu.")
