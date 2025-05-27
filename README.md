# Detector de Phishing em Python

Este projeto fornece uma ferramenta completa em Python para detecção de URLs de phishing, com análise heurística avançada e interface web interativa.

---

## Tecnologias e Dependências

* Python 3.8+
* Flask
* Requests
* tldextract
* python-whois
* dnspython
* cryptography
* beautifulsoup4
* python-Levenshtein
* plotly

Instale com:

```bash
pip install -r requirements.txt
```

---

## Estrutura do Projeto

```
├── app.py             # Aplicação Flask
├── detector.py        # Lógica de análise de phishing
├── requirements.txt   # Dependências
├── history.db         # Banco SQLite (criado automaticamente)
└── templates/         # Templates HTML
    ├── index.html
    ├── results.html
    └── history.html
```

---

## Uso

1. Execute a aplicação:

   ```bash
   python app.py
   ```
2. Acesse em `http://localhost:5000`:

   * **Index**: insira uma URL para verificar
   * **Resultados**: score, probabilidade e gráfico gauge
   * **Histórico**: lista de URLs verificadas e gráfico de distribuição

---

## Configuração

* **PHISHTANK\_LIST** em `detector.py`: atualize com sua lista de domínios maliciosos
* **BRANDS** no `app.py`: domínios de marcas conhecidas para análise de similaridade
* Ajuste thresholds de score e distância de Levenshtein conforme necessidade




