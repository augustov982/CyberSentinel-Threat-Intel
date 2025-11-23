#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
CYBERSENTINEL ULTIMATE - Threat Intelligence & Fraud Prevention Pipeline.
Autor: Augusto V.
Versão: 7.0 (Enterprise Edition - Batch & Interactive)
"""

import sys
import os
import json
import re
import time
import argparse
import datetime
import requests
import dns.resolver
import phonenumbers
from phonenumbers import geocoder, carrier
from bs4 import BeautifulSoup
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from colorama import Fore, Style, init

# Inicializa colorama para logs coloridos
init(autoreset=True)

# ==============================================================================
# CONFIGURAÇÕES GLOBAIS
# ==============================================================================

# API KEY DO VIRUSTOTAL (Mantida a que você forneceu)
VT_API_KEY = os.getenv('VT_API_KEY', 'API_VIRUSTOTAL_AQUI')

# CONFIGURAÇÃO DA IA LOCAL (OLLAMA)
OLLAMA_URL = "http://localhost:11434/api/generate"
AI_MODEL = "llama3"#coloque aqui o modelo local

# LISTA DE BLACKLISTS DNS (RBL)
BLACKLISTS = [
    "zen.spamhaus.org", "bl.spamcop.net", "b.barracudacentral.org",
    "cbl.abuseat.org", "dnsbl.sorbs.net", "spam.dnsbl.sorbs.net",
    "ix.dnsbl.manitu.net", "bl.spamcannibal.org", "psbl.surriel.com",
    "dnsbl-1.uceprotect.net", "virus.rbl.jp", "phishing.rbl.jp"
]

# ==============================================================================
# MÓDULO 1: DETECÇÃO DE INPUT E IDENTIDADE
# ==============================================================================

class InputDetector:
    @staticmethod
    def detect(target):
        # Limpeza básica
        clean_target = re.sub(r'\s+', '', target)
        nums_only = re.sub(r'\D', '', clean_target)

        # Regex Patterns
        ip_pattern = r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$"
        email_pattern = r"[^@]+@[^@]+\.[^@]+"

        if re.match(ip_pattern, clean_target):
            return "IP", clean_target
        
        # CPF: 11 dígitos numéricos (com ou sem pontuação)
        if len(nums_only) == 11 and ('.' in target or '-' in target or target.isdigit()):
            return "CPF", nums_only
        
        # Telefone: Entre 10 e 13 dígitos (ex: 11999998888 ou 5511...)
        if 10 <= len(nums_only) <= 13:
            return "PHONE", clean_target

        if re.match(email_pattern, clean_target):
            return "EMAIL", clean_target

        # Padrão URL/Domínio
        return "DOMAIN", clean_target

class IdentityProfiler:
    """Validação matemática e OSINT de documentos e telefones"""
    
    def analyze_cpf(self, cpf):
        print(f"{Fore.CYAN}[ID] Iniciando validação matemática e fiscal do CPF...")
        
        # 1. Validação de Formato
        if len(cpf) != 11 or cpf == cpf[0] * 11:
            return {"valid": False, "status": "INVALID_FORMAT", "risk": "HIGH"}
            
        # 2. Algoritmo Módulo 11 (Receita Federal)
        for i in range(9, 11):
            value = sum((int(cpf[num]) * ((i + 1) - num) for num in range(0, i)))
            digit = ((value * 10) % 11) % 10
            if digit != int(cpf[i]):
                return {"valid": False, "status": "INVALID_CHECK_DIGIT", "risk": "CRITICAL (Fake Generator)"}
        
        # 3. Região Fiscal
        regions = {
            '1': 'DF, GO, MS, MT, TO', '2': 'AC, AM, AP, PA, RO, RR',
            '3': 'CE, MA, PI', '4': 'AL, PB, PE, RN', '5': 'BA, SE',
            '6': 'MG', '7': 'ES, RJ', '8': 'SP', '9': 'PR, SC', '0': 'RS'
        }
        
        return {
            "valid": True,
            "status": "VALID",
            "formatted": f"{cpf[:3]}.***.***-{cpf[9:]}", # Mascaramento LGPD
            "fiscal_region": regions.get(cpf[8], "Unknown"),
            "risk": "LOW (Structurally Valid)"
        }

    def analyze_phone(self, phone):
        print(f"{Fore.CYAN}[ID] Iniciando intel de telefonia (Carrier/Geo)...")
        try:
            if not phone.startswith("+"):
                phone = "+55" + re.sub(r'\D', '', phone)
            
            parsed = phonenumbers.parse(phone, None)
            if not phonenumbers.is_valid_number(parsed):
                return {"valid": False, "status": "INVALID_NUMBER"}
            
            return {
                "valid": True,
                "formatted": phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.INTERNATIONAL),
                "carrier": carrier.name_for_number(parsed, "pt-br") or "Unknown/VoIP",
                "location": geocoder.description_for_number(parsed, "pt-br"),
                "type": "Mobile" if phonenumbers.number_type(parsed) == phonenumbers.PhoneNumberType.MOBILE else "Landline/Fixed"
            }
        except Exception as e:
            return {"valid": False, "error": str(e)}

# ==============================================================================
# MÓDULO 2: INFRAESTRUTURA E REDE
# ==============================================================================

class NetworkScanner:
    def get_rdap(self, domain):
        print(f"{Fore.CYAN}[NET] Consultando RDAP/Whois BR...")
        try:
            # Remove http/https e paths
            clean_domain = domain.replace("https://", "").replace("http://", "").split('/')[0]
            r = requests.get(f"https://rdap.registro.br/domain/{clean_domain}", timeout=5)
            if r.status_code == 200:
                return r.json()
            return {"error": f"RDAP Status {r.status_code}"}
        except:
            return {"error": "Connection Failed"}

    def resolve_dns(self, domain):
        print(f"{Fore.CYAN}[NET] Mapeando registros DNS...")
        clean_domain = domain.replace("https://", "").replace("http://", "").split('/')[0]
        records = {}
        try:
            # Tenta resolver IP (A)
            try:
                a_records = dns.resolver.resolve(clean_domain, 'A')
                records['ip'] = [r.to_text() for r in a_records]
            except: records['ip'] = []

            # Tenta resolver MX (Email)
            try:
                mx_records = dns.resolver.resolve(clean_domain, 'MX')
                records['mx'] = [r.to_text() for r in mx_records]
            except: records['mx'] = []
            
            return records
        except:
            return {"error": "DNS Resolution Failed"}

# ==============================================================================
# MÓDULO 3: WEB AUDITOR (PHISHING & MALWARE)
# ==============================================================================

class WebAuditor:
    def __init__(self):
        self.headers = {'User-Agent': 'Mozilla/5.0 (CyberSentinel Security Scanner v6.0)'}
        self.phishing_keywords = [
            "senha", "password", "cpf", "cartão", "credit card", 
            "bloquead", "atualiz", "token", "cvv", "segurança"
        ]

    def deep_scan(self, url):
        if not url.startswith("http"): url = "http://" + url
        print(f"{Fore.CYAN}[WEB] Iniciando Deep Scan HTML em: {url}...")
        
        result = {"scanned": False, "findings": []}
        
        try:
            r = requests.get(url, headers=self.headers, timeout=5, verify=False)
            result['status_code'] = r.status_code
            result['scanned'] = True
            
            soup = BeautifulSoup(r.text, 'html.parser')
            
            # 1. Busca inputs de Senha (Password Harvesters)
            pass_inputs = soup.find_all('input', {'type': 'password'})
            if pass_inputs:
                result['findings'].append(f"{Fore.RED}CRÍTICO: {len(pass_inputs)} campos de senha detectados (Possível Phishing).")

            # 2. Busca Iframes Ocultos (Drive-by Download)
            iframes = soup.find_all('iframe')
            for iframe in iframes:
                style = str(iframe.get('style')).lower()
                if 'display:none' in style or 'visibility:hidden' in style or iframe.get('width') == '0':
                    result['findings'].append(f"{Fore.RED}MALWARE: Iframe invisível/oculto detectado.")

            # 3. Busca Palavras-chave de Engenharia Social
            text = soup.get_text().lower()
            found_keywords = [k for k in self.phishing_keywords if k in text]
            if found_keywords:
                result['findings'].append(f"{Fore.YELLOW}SOCIAL ENG: Termos suspeitos encontrados: {found_keywords}")

            # 4. Detecção de CMS Desatualizado
            meta_gen = soup.find("meta", {"name": "generator"})
            if meta_gen:
                result['tech_stack'] = meta_gen.get('content')

        except Exception as e:
            result['error'] = str(e)

        return result

# ==============================================================================
# MÓDULO 4: REPUTATION ENGINE (VT & RBLs)
# ==============================================================================

class ReputationEngine:
    def check_virustotal(self, domain):
        if "SUA_KEY" in VT_API_KEY:
            return {"status": "Skipped (No API Key)"}
            
        print(f"{Fore.CYAN}[REP] Consultando VirusTotal API v3...")
        domain_clean = domain.replace("https://", "").replace("http://", "").split('/')[0]
        
        headers = {"x-apikey": VT_API_KEY}
        try:
            r = requests.get(f"https://www.virustotal.com/api/v3/domains/{domain_clean}", headers=headers)
            if r.status_code == 200:
                data = r.json()['data']['attributes']['last_analysis_stats']
                return data
            elif r.status_code == 404:
                return {"status": "Clean (Not found in DB)"}
            else:
                return {"error": f"VT Error {r.status_code}"}
        except Exception as e:
            return {"error": str(e)}

    def check_blacklists(self, ip_list):
        if not ip_list: return []
        target_ip = ip_list[0] # Pega o primeiro IP resolvido
        print(f"{Fore.CYAN}[REP] Verificando IP {target_ip} em {len(BLACKLISTS)} RBLs (Multi-threaded)...")
        
        listed_on = []
        
        def check_one(rbl):
            try:
                query = '.'.join(reversed(target_ip.split('.'))) + "." + rbl
                dns.resolver.resolve(query, 'A')
                return rbl
            except: return None

        with ThreadPoolExecutor(max_workers=20) as executor:
            futures = [executor.submit(check_one, rbl) for rbl in BLACKLISTS]
            for future in as_completed(futures):
                res = future.result()
                if res: 
                    print(f"{Fore.RED}   [!] ALERTA: Listado em {res}")
                    listed_on.append(res)
        
        return listed_on if listed_on else ["IP Limpo (Clean)"]

# ==============================================================================
# MÓDULO 5: AI ORCHESTRATOR (OLLAMA)
# ==============================================================================

class AIOrchestrator:
    def analyze(self, full_data, data_type):
        print(f"\n{Fore.MAGENTA}[AI] Enviando Dossiê Completo para Llama3 Local...")
        
        prompt = f"""
        Aja como um Especialista Sênior em Cyber Security e Prevenção a Fraudes.
        Analise os dados JSON abaixo e gere um relatório executivo em Português (Brasil).
        
        TIPO DE ALVO: {data_type}
        DADOS COLETADOS:
        {json.dumps(full_data, indent=2)}
        
        DIRETRIZES:
        1. Se for CPF/Telefone: Verifique a validade matemática e a consistência da operadora.
        2. Se for Domínio/URL: Correlacione a idade do domínio (RDAP) com os achados do site (WebAuditor).
           - Se tiver campos de senha E domínio novo = PHISHING.
           - Se VirusTotal > 0 malicioso = MALWARE.
        3. Se for IP: Verifique se está em Blacklists.
        
        SAÍDA ESPERADA:
        - VEREDITO: (Legítimo / Suspeito / Malicioso)
        - PONTOS DE ATENÇÃO: (Liste as evidências técnicas)
        - RECOMENDAÇÃO: (Bloquear / Monitorar / Takedown / Aprovar)
        """

        try:
            r = requests.post(OLLAMA_URL, json={"model": AI_MODEL, "prompt": prompt, "stream": False})
            if r.status_code == 200:
                return r.json()['response']
            return f"Erro na IA: Status {r.status_code}"
        except:
            return "Erro: Não foi possível conectar ao Ollama (localhost:11434)."

# ==============================================================================
# LOGICA DE CONTROLE E MENU
# ==============================================================================

def process_single_target(target_input):
    """Função wrapper que executa a lógica para um único alvo"""
    # 2. Identificação
    detector = InputDetector()
    target_type, clean_target = detector.detect(target_input)
    
    print(f"{Style.BRIGHT}{Fore.BLUE}" + "="*60)
    print(f" CYBERSENTINEL v7.0 | Target: {target_input} | Type: {target_type}")
    print("="*60 + f"{Style.RESET_ALL}\n")

    # 3. Coleta de Dados (Pipeline Dinâmico)
    evidence = {"target": target_input, "type": target_type, "timestamp": str(datetime.datetime.now())}

    # Ramo de Identidade
    if target_type in ["CPF", "PHONE"]:
        profiler = IdentityProfiler()
        if target_type == "CPF":
            evidence['identity_analysis'] = profiler.analyze_cpf(clean_target)
        else:
            evidence['identity_analysis'] = profiler.analyze_phone(clean_target)

    # Ramo de Infra/Web
    elif target_type in ["DOMAIN", "IP", "EMAIL"]:
        net = NetworkScanner()
        web = WebAuditor()
        rep = ReputationEngine()
        
        # Se for Email, extrai o domínio
        domain_to_scan = clean_target.split('@')[1] if target_type == "EMAIL" else clean_target
        
        # Coletas
        evidence['dns'] = net.resolve_dns(domain_to_scan)
        evidence['rdap'] = net.get_rdap(domain_to_scan)
        
        # Web Scan (apenas se for domínio/url)
        if target_type == "DOMAIN":
            evidence['web_audit'] = web.deep_scan(domain_to_scan)
        
        # Reputação
        evidence['virustotal'] = rep.check_virustotal(domain_to_scan)
        evidence['blacklists'] = rep.check_blacklists(evidence['dns'].get('ip', []))

    # 4. Análise da IA
    ai = AIOrchestrator()
    evidence['verdict'] = ai.analyze(evidence, target_type)
    
    return evidence

def run_batch_mode(filepath):
    """Lê um arquivo e processa múltiplos alvos com Resumo em Tempo Real"""
    if not os.path.exists(filepath):
        print(f"{Fore.RED}[!] Arquivo não encontrado: {filepath}")
        return

    print(f"{Fore.YELLOW}[!] Iniciando Scan em Massa no arquivo: {filepath}")
    print(f"{Fore.WHITE}    Os resultados detalhados irão para o JSON. Abaixo apenas o resumo executivo.\n")
    
    with open(filepath, 'r') as f:
        targets = [line.strip() for line in f if line.strip()]
    
    full_report = []
    timestamp = int(time.time())

    for i, target in enumerate(targets):
        # Imprime separador visual
        print(f"{Style.BRIGHT}{Fore.BLUE}" + "-"*60)
        print(f"{Fore.WHITE}>>> Alvo {i+1}/{len(targets)}: {target}")
        
        # Processa (Faz toda a mágica)
        result = process_single_target(target)
        full_report.append(result)

        # --- LÓGICA DE RESUMO NO TERMINAL ---
        verdict_text = result.get('verdict', 'Sem resposta da IA').strip()
        
        # Tenta extrair métricas rápidas
        vt_data = result.get('vt', {})
        malicious_vt = 0
        if isinstance(vt_data, dict):
             malicious_vt = vt_data.get('malicious', 0)
        
        blacklists_count = len(result.get('blacklists', []))
        
        # Define cor baseada no risco
        risk_color = Fore.GREEN
        status_tag = "[CLEAN]"
        
        # Se tiver malware no VT, Blacklist ou palavras-chave ruins na IA
        if malicious_vt > 0 or blacklists_count > 0 or \
           any(x in verdict_text.lower() for x in ['malicioso', 'phishing', 'crítico', 'fraud', 'perigo']):
            risk_color = Fore.RED
            status_tag = "[CRÍTICO/MALICIOUS]"
        elif "suspeito" in verdict_text.lower() or "atenção" in verdict_text.lower():
            risk_color = Fore.YELLOW
            status_tag = "[SUSPEITO/WARNING]"

        # Imprime o Resumo
        print(f"\n{risk_color}{status_tag} RESUMO DO VEREDITO:")
        # Imprime as primeiras 3 linhas da IA ou 200 caracteres para não poluir
        summary_text = verdict_text.replace('\n', ' ')[:250] + "..."
        print(f"{Fore.WHITE}{summary_text}")
        
        # Imprime Estatísticas Técnicas Rápidas
        print(f"{Style.DIM}Stats: VirusTotal Malicious: {malicious_vt} | Blacklists: {blacklists_count}")
        print(f"{Style.RESET_ALL}")

    # Salva o Relatório Completo
    outfile = f"batch_report_{timestamp}.json"
    with open(outfile, 'w', encoding='utf-8') as f:
        json.dump(full_report, f, indent=4, ensure_ascii=False)
    
    print(f"\n{Style.BRIGHT}{Fore.GREEN}" + "="*60)
    print(f"[SUCESSO] Batch finalizado! Relatório Completo salvo em: {outfile}")
    print("="*60)

def print_banner():
    print(f"{Style.BRIGHT}{Fore.BLUE}")
    print(r"""
   _______   __________  __________  _____  ____  ______  ________   ____  __
  / ___/ /  / ____/ / / /  _/ __ \/ __ \/ __ \/  _/ / / / ____/ | / / / / /
 / /__/ /_ / / __/ /_/ // // /_/ / / / / /_/ // // / / / __/ /  |/ / / / / 
 \___/___//_/ /_/\__, /___/____ /_/ /_/____/___/_/ /_/_____/_/|___/_/_/_/  
    """)
    print(f"{Fore.WHITE}    CyberSentinel v7.0 - Enterprise Edition")
    print(f"{Style.RESET_ALL}")

# ==============================================================================
# MAIN PIPELINE
# ==============================================================================

def main():
    print_banner()

    parser = argparse.ArgumentParser(description="CyberSentinel Ultimate - Threat Intel Automation")
    parser.add_argument("target", nargs='?', help="Alvo único OU caminho do arquivo .txt (Opcional se quiser usar Menu)")
    parser.add_argument("--batch", action="store_true", help="Indica que o input é um arquivo de lista")
    args = parser.parse_args()

    # MODO CLI (Se passar argumento)
    if args.target:
        if args.batch or args.target.endswith('.txt'):
            run_batch_mode(args.target)
        else:
            evidence = process_single_target(args.target)
            # Output Final
            print("\n" + "="*60)
            print(f"{Style.BRIGHT}{Fore.YELLOW}RELATÓRIO DE INTELIGÊNCIA ARTIFICIAL:")
            print("="*60)
            print(Fore.WHITE + evidence.get('verdict', 'Sem Veredito'))
            print("\n" + "="*60)
            
            # Salva Log
            filename = f"log_{evidence['type']}_{int(time.time())}.json"
            with open(filename, 'w') as f:
                json.dump(evidence, f, indent=4)
            print(f"{Fore.GREEN}[LOG] Evidência técnica salva em: {filename}")
        return

    # MODO INTERATIVO (Menu)
    while True:
        print(f"\n{Fore.CYAN}ESCOLHA UMA OPÇÃO:")
        print(f"{Fore.WHITE}1. Análise de Alvo Único (IP, Domínio, CPF, etc)")
        print(f"{Fore.WHITE}2. Análise em Massa (Arquivo .txt)")
        print(f"{Fore.RED}3. Sair")
        
        choice = input(f"\n{Fore.GREEN}>> Digite a opção: {Style.RESET_ALL}").strip()

        if choice == '1':
            t = input("Digite o alvo: ").strip()
            if t:
                res = process_single_target(t)
                print(f"\n{Fore.YELLOW}VEREDITO: {res.get('verdict')}")
                input("\n[Enter] para voltar...")
        
        elif choice == '2':
            f = input("Caminho do arquivo .txt: ").strip()
            run_batch_mode(f)
            input("\n[Enter] para voltar...")
        
        elif choice == '3':
            sys.exit()

if __name__ == "__main__":
    main()