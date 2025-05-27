import re
import socket
import ssl
import datetime
import whois
import dns.resolver
import requests
import tldextract
from bs4 import BeautifulSoup
from rapidfuzz.distance import Levenshtein
from urllib.parse import urlparse
import requests
import tldextract
from functools import lru_cache



def levenshtein_distance(a, b):
    return Levenshtein.distance(a, b)
PHISHTANK_LIST = {'bad-domain.com', 'malicious.org'}


def in_phishtank(domain: str) -> bool:
    return domain in PHISHTANK_LIST


def suspicious_url_features(url: str) -> dict:
    """Verificações básicas de Conceito C."""
    parsed = tldextract.extract(url)
    domain = parsed.registered_domain
    return {
        'numeros_no_dominio': bool(re.search(r'\d', domain)),
        'muitos_subdominios': len(parsed.subdomain.split('.')) > 2,
        'chars_especiais': bool(re.search(r'[^a-zA-Z0-9\.-]', url)),
    }


def domain_age_days(domain: str) -> int:
    """Idade do domínio em dias (Conceito B)."""
    w = whois.whois(domain)
    created = w.creation_date
    if isinstance(created, list):
        created = created[0]
    return (datetime.datetime.now() - created).days if created else -1


def uses_dynamic_dns(domain: str) -> bool:
    """Detecta provedores de DNS dinâmico."""
    dyn = ['no-ip.org', 'dyndns.org', 'duckdns.org']
    return any(domain.endswith(d) for d in dyn)


def ssl_info(domain: str) -> dict:

    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
            s.settimeout(3)
            s.connect((domain, 443))
            cert = s.getpeercert()

        exp = datetime.datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
        issuer = dict(x[0] for x in cert.get('issuer', ()))
        san = cert.get('subjectAltName', ())
        return {
            'issuer': issuer.get('O', ''),
            'expires_in': (exp - datetime.datetime.now()).days,
            'match_domain': any(domain == entry[1] for entry in san if entry[0].lower() == 'dns'),
            'ssl_error': None
        }

    except Exception as e:
        return {
            'issuer': '',
            'expires_in': None,
            'match_domain': False,
            'ssl_error': str(e)
        }


def levenshtein_similar(domain: str, brands: list) -> tuple:
    """Compara com domínios de marcas conhecidas."""
    best = min(brands, key=lambda b: levenshtein_distance(domain, b))
    dist = levenshtein_distance(domain, best)
    return best, dist


def content_analysis(url: str) -> dict:
    """Busca formulários de login e campos sensíveis."""
    r = requests.get(url, timeout=5)
    soup = BeautifulSoup(r.text, 'html.parser')
    forms = soup.find_all('form')
    login_forms = [f for f in forms if any(
        inp.get('type') == 'password' for inp in f.find_all('input'))]
    return {
        'total_forms': len(forms),
        'login_forms': len(login_forms)
    }


def check_redirects(url: str) -> bool:
    """Detecta redirecionamentos suspeitos."""
    r = requests.get(url, timeout=5, allow_redirects=True)
    return r.url != url


def analyze_url(raw_url: str, known_brands: list) -> dict:
    """
    Analisa uma URL e retorna um dict com várias features e um flag 'is_phishing'.
    Já faz normalização de esquema e captura erros de rede.
    """
    url = raw_url.strip()
    if not urlparse(url).scheme:
        url = 'http://' + url

    ext = tldextract.extract(url)
    domain = ext.registered_domain

    base = {
        'url': url,
        'domain': domain,
        'in_phishtank': in_phishtank(domain),
        **suspicious_url_features(url),        
        'domain_age_days': domain_age_days(domain),
        'dynamic_dns': uses_dynamic_dns(domain),
        **ssl_info(domain),                   
        'redirected': False,
        'total_forms': None,
        'login_forms': None,
    }

    try:
        base['redirected'] = check_redirects(url)
    except Exception as e:
        base['redirected_error'] = str(e)

    try:
        c = content_analysis(url)
        base['total_forms'] = c.get('total_forms', 0)
        base['login_forms'] = c.get('login_forms', 0)
    except Exception as e:
        base['content_error'] = str(e)

    best_brand, lev_dist = levenshtein_similar(domain, known_brands)
    base['closest_brand'] = best_brand
    base['lev_distance']   = lev_dist

    result = { **base, 'is_phishing': False }

    score = (
        int(result['in_phishtank']) +
        int(result['numeros_no_dominio']) +
        int(result['muitos_subdominios']) +
        int(result['chars_especiais']) +
        int(result['domain_age_days'] is not None and result['domain_age_days'] < 30) +
        int(result['dynamic_dns']) +
        int(not result['match_domain']) +
        int(result['redirected']) +
        int((result['login_forms'] or 0) > 0) +
        int(result['lev_distance'] < 3)
    )

    result['phishing_score'] = score
    result['is_phishing']    = (score >= 3)

    return result

