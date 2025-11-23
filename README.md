# 🛡️ CyberSentinel - AI Threat Intelligence Pipeline

> **Ferramenta de Automação de OSINT & Prevenção a Fraudes com IA Local (Llama3)**

![Python](https://img.shields.io/badge/Python-3.9%2B-blue)
![AI](https://img.shields.io/badge/AI-Llama3-purple)
![Security](https://img.shields.io/badge/Security-OSINT-red)

O **CyberSentinel** é uma ferramenta de linha de comando (CLI) "Enterprise-Grade" desenvolvida para automatizar a investigação de artefatos suspeitos. Ela unifica a coleta de dados de infraestrutura, reputação e identidade, utilizando **Inteligência Artificial Generativa** local para correlacionar os dados e emitir um veredito de risco.

Projeto desenvolvido com foco em **Threat Intelligence**, **Prevenção a Fraudes** e **Resposta a Incidentes**.

## 🚀 Principais Funcionalidades

*   **🧠 Vereditos via IA:** Integração nativa com **Ollama (Llama3)** rodando localmente para analisar JSONs técnicos e gerar resumos executivos em Português.
*   **🎣 Deep Phishing Scan:** Crawler autônomo que acessa URLs suspeitas para detectar:
    *   Campos de captura de senha ocultos.
    *   Ataques de *Meta-Refresh* e Redirecionamentos.
    *   JavaScript ofuscado ou malicioso.
*   **🌍 Análise de Infraestrutura:** Consultas automatizadas de RDAP/Whois (Registro.br) e enumeração de DNS.
*   **🚫 Motor de Reputação:** Verificação simultânea (Multi-threaded) em **12+ Blacklists (RBLs)** e integração com API v3 do **VirusTotal**.
*   **🆔 Validação de Identidade:** Validação matemática de CPFs (Algoritmo Módulo 11/Receita Federal) e identificação de operadoras de telefonia (Detecção de VoIP).
*   **⚡ Processamento em Massa:** Modo *Batch* para analisar listas de milhares de alvos simultaneamente.

## 🛠️ Instalação

1. Clone o repositório:
   ```bash
   git clone https://github.com/augustov982/CyberSentinel-Threat-Intel.git

Instale as dependências:
   pip install -r requirements.txt

   (Opcional) Configure sua chave do VirusTotal:
Crie um arquivo .env ou exporte no terminal:

Garanta que o Ollama esteja rodando localmente:
ollama run llama3


💻 Como Usar
1. Modo Interativo (Menu)
Basta rodar o script sem argumentos:

python sentinel_ultimate.py


2. Modo CLI (Alvo Único)
Para automações rápidas ou pipelines CI/CD:

python sentinel_ultimate.py google.com
python sentinel_ultimate.py 11999998888
python sentinel_ultimate.py "http://site-phishing.com/login"


📊 Exemplo de Saída (Terminal)
[CRÍTICO/MALICIOUS] RESUMO DO VEREDITO:
Veredito: MALICIOSO (Phishing Confirmado). O domínio foi registrado há apenas 2 dias e contém inputs de senha detectados pelo WebAuditor. Além disso, o IP está listado em 12 Blacklists. Recomendação: Takedown imediato.

Stats: VirusTotal Malicious: 4 | Blacklists: 12

Desenvolvido para fins educacionais e de pesquisa em defesa cibernética.

👨‍💻 Autor
Desenvolvido por Augusto V.
