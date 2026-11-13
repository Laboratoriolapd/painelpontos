#!/usr/bin/env python3
"""Coleta dados do Ponto Web (Secullum) e grava data.json para o dashboard.

Variáveis de ambiente:
  SECULLUM_USER, SECULLUM_PASS   usuário da Conta Secullum (ideal: usuário só de integração)
  SECULLUM_BANCO_ID              opcional; se vazio, usa o primeiro banco da conta e lista os disponíveis
  MAX_CALC                       máx. de chamadas a /Calcular por execução (padrão 90; limite da API: 100/h)
  OUT                            caminho do JSON de saída (padrão data.json)
"""
import base64, os, re, sys, json, unicodedata, datetime as dt
from collections import defaultdict
import requests



def env_usuario(nome):
    """Variável de ambiente; se faltar (tarefa agendada), tenta as variáveis do usuário no Windows."""
    v = os.environ.get(nome)
    if v:
        return v
    try:
        import winreg
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, "Environment") as k:
            return winreg.QueryValueEx(k, nome)[0]
    except Exception:
        return None


USER, PASS = env_usuario("SECULLUM_USER"), env_usuario("SECULLUM_PASS")
if not USER or not PASS:
    sys.exit("Faltam SECULLUM_USER e SECULLUM_PASS. Rode: python instalar_automatico.py")
BANCO = env_usuario("SECULLUM_BANCO_ID")

# MODO NUVEM (GitHub): com PAINEL_SENHA definida, os dados saem CRIPTOGRAFADOS (site/data.enc) e nada em texto aberto é gravado.
SENHA_PAINEL = os.environ.get("PAINEL_SENHA")
NUVEM = bool(SENHA_PAINEL)
if NUVEM and len(SENHA_PAINEL) < 12:
    sys.exit("A senha do painel (PAINEL_SENHA) precisa ter pelo menos 12 caracteres. Use uma frase longa.")


def _chave(senha, sal, iteracoes):
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    return PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=sal, iterations=iteracoes).derive(senha.encode("utf-8"))


def cifra(obj, senha, iteracoes=600000):
    """AES-256-GCM com chave derivada da senha (PBKDF2-SHA256). O painel (navegador) decifra com a mesma senha."""
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    sal, iv = os.urandom(16), os.urandom(12)
    claro = json.dumps(obj, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    c = AESGCM(_chave(senha, sal, iteracoes)).encrypt(iv, claro, None)
    b = lambda x: base64.b64encode(x).decode()
    return {"v": 1, "k": iteracoes, "s": b(sal), "i": b(iv), "c": b(c)}


def decifra(env, senha):
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    d = base64.b64decode
    claro = AESGCM(_chave(senha, d(env["s"]), env["k"])).decrypt(d(env["i"]), d(env["c"]), None)
    return json.loads(claro.decode("utf-8"))


def miniatura(dados, lado=96):
    """Foto reduzida e recortada em quadrado (rosto no alto), como data URI, para caber nos dados criptografados."""
    try:
        import io
        from PIL import Image
        im = Image.open(io.BytesIO(dados)).convert("RGB")
        w, h = im.size
        m = min(w, h)
        esq, topo = (w - m) // 2, (h - m) // 3
        im = im.crop((esq, topo, esq + m, topo + m)).resize((lado, lado))
        saida = io.BytesIO()
        im.save(saida, "JPEG", quality=72)
        return "data:image/jpeg;base64," + base64.b64encode(saida.getvalue()).decode()
    except Exception as e:
        print("Não consegui reduzir uma foto (o pacote pillow está instalado?):", e)
        return None
AUTH = "https://autenticador.secullum.com.br"
API = "https://pontowebintegracaoexterna.secullum.com.br/IntegracaoExterna"
MAX_CALC = int(os.environ.get("MAX_CALC", "90"))
OUT, CACHE = os.environ.get("OUT", "data.json"), "calc_cache.json"
OUT_ENC = os.environ.get("OUT_ENC", "site/data.enc")  # modo nuvem: dados criptografados que vão para o site
ESTADO_ENC = os.environ.get("ESTADO_ENC", "estado.enc")  # modo nuvem: cálculos e fotos já obtidos, criptografados
h_ent, m_ent = os.environ.get("HORA_ENTRADA", "08:00").split(":")
LIMITE_ENTRADA = int(h_ent) * 60 + int(m_ent)  # horário de entrada, em minutos
TOLERANCIA = int(os.environ.get("TOLERANCIA_MIN", "10"))  # minutos de tolerância
SIG_SALDO = None  # definido abaixo
CAMPOS_BATIDA = [f"{t}{i}" for i in range(1, 6) for t in ("Entrada", "Saida")]  # campos de horário da rota Batidas
# Funcionários FORA de todos os cálculos e telas do painel (pode ser só parte do nome). Para incluir mais gente,
# acrescente nomes entre aspas, separados por vírgula. Também vale o arquivo excluir.txt e a variável EXCLUIR_NOMES.
EXCLUIR_PADRAO = []  # na nuvem a lista vem do Secret EXCLUIR_NOMES (nomes separados por ponto e vírgula)
SALDO_MODO = os.environ.get("SALDO_MODO", "calculado")  # "calculado" = extras - faltas; "total"/"ultimo" = lê COLUNA_SALDO do relatório
SALDO_ATRASOS = os.environ.get("SALDO_ATRASOS") == "1"  # 1 = o saldo calculado também desconta os atrasos
COLUNA_SALDO = os.environ.get("COLUNA_SALDO", "BSaldo")  # coluna do cálculo usada como saldo de horas (pode ser negativa)
digitos = lambda v: re.sub(r"\D", "", str(v or ""))


def norm(nome):  # compara nomes sem acento, caixa ou espaços duplicados
    t = unicodedata.normalize("NFKD", nome or "").encode("ascii", "ignore").decode()
    return re.sub(r"\s+", " ", t).upper().strip()


# valor da hora de cada funcionário (arquivo valores_hora.json, na mesma pasta deste script)
ARQ_VALORES = os.path.join(os.path.dirname(os.path.abspath(__file__)), "valores_hora.json")
VALORES = {}
if os.environ.get("VALORES_HORA"):
    VALORES = {norm(k): float(v) for k, v in json.loads(os.environ["VALORES_HORA"]).items()}
    print(f"VALORES_HORA: {len(VALORES)} valores lidos")
elif os.path.exists(ARQ_VALORES):
    VALORES = {norm(k): float(v) for k, v in json.load(open(ARQ_VALORES, encoding="utf-8")).items()}
    print(f"valores_hora.json: {len(VALORES)} valores lidos")
else:
    print("ATENÇÃO: valores_hora.json não encontrado em", ARQ_VALORES)


SIG_SALDO = f"{COLUNA_SALDO}|{SALDO_MODO}|{int(SALDO_ATRASOS)}|ate-ontem"  # muda quando a coluna/modo do saldo muda -> refaz os cálculos
DIAG = norm(os.environ.get("DIAGNOSTICO", ""))  # parte do nome de um funcionário, para investigar o saldo
SALDO_ESPERADO = os.environ.get("SALDO_ESPERADO", "")  # saldo que o sistema mostra para ele, ex.: 6:47


def acha_valor(nome):
    """Acha a chave de VALORES para um nome: igual; ou primeiro+último nome iguais; ou muito parecido."""
    n = norm(nome)
    if n in VALORES:
        return n
    t = n.split()
    if not t:
        return None
    cand = [k for k in VALORES if k.split()[0] == t[0] and k.split()[-1] == t[-1]]
    if len(cand) == 1:
        return cand[0]
    import difflib
    best = difflib.get_close_matches(n, list(VALORES), n=1, cutoff=0.85)
    return best[0] if best else None


# ---- fotos dos funcionários: pasta "fotos" ao lado deste script ----
PASTA_FOTOS = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fotos")
EXT_FOTO = (".jpg", ".jpeg", ".png", ".webp", ".gif")
MAX_FOTOS = int(os.environ.get("MAX_FOTOS", "60"))  # downloads por rodada
ATUALIZAR_FOTOS = os.environ.get("ATUALIZAR_FOTOS") == "1"  # 1 = baixa de novo mesmo as que já existem


def nome_arquivo(nome):
    return re.sub(r'[<>:"/\\|?*\x00-\x1f]', "", nome or "").strip()


def indexa_fotos():
    """{nome normalizado: arquivo} das fotos que já estão na pasta (baixadas ou colocadas à mão)."""
    d = {}
    for arq in os.listdir(PASTA_FOTOS):
        stem, ext = os.path.splitext(arq)
        if ext.lower() in EXT_FOTO:
            s2, e2 = os.path.splitext(stem)  # "NOME.jpg.jpg": o Windows esconde a extensão e ela pode ter sido digitada duas vezes
            if e2.lower() in EXT_FOTO:
                stem = s2
            d[norm(stem)] = arq
    return d


def liga_fotos(nomes, fotos):
    """{nome do funcionário: arquivo}. 1º nome igual (sem acento/caixa); 2º arquivo cujas palavras estão todas
    no nome do funcionário (ex.: 'Maria Silva'), desde que só um funcionário se encaixe."""
    liga = {n: fotos[norm(n)] for n in nomes if norm(n) in fotos}
    usados = set(liga.values())
    for k, arq in fotos.items():
        if arq in usados or not k:
            continue
        palavras = set(k.split())
        cand = [n for n in nomes if n not in liga and palavras <= set(norm(n).split())]
        if len(cand) == 1:
            liga[cand[0]] = arq
            usados.add(arq)
    return liga


def acha_arquivo(nome, fotos):
    """Foto do funcionário: nome igual (sem acento/caixa) ou, se só houver um, mesmo primeiro e último nome."""
    n = norm(nome)
    if n in fotos:
        return fotos[n]
    t = n.split()
    if not t:
        return None
    cand = [a for k, a in fotos.items() if k.split() and k.split()[0] == t[0] and k.split()[-1] == t[-1]]
    return cand[0] if len(cand) == 1 else None


def extrai_imagem(r):
    """Resposta da rota Funcionarios/fotos -> (bytes, extensão) ou None. Aceita imagem direta, base64 ou JSON."""
    if r.status_code in (204, 404):
        return None
    r.raise_for_status()
    if r.headers.get("Content-Type", "").lower().startswith("image/"):
        dados = r.content
    else:
        txt = r.text.strip()
        if txt[:1] in "{[":
            try:
                j = r.json()
                if isinstance(j, list) and j:
                    j = j[0]
                if isinstance(j, dict):
                    j = next((v for k, v in j.items() if "foto" in k.lower() or "imagem" in k.lower()), "")
                txt = str(j or "")
            except ValueError:
                return None
        txt = txt.strip().strip('"')
        m = re.match(r"data:image/\w+;base64,(.*)", txt, re.S)
        txt = m.group(1) if m else txt
        if not txt:
            return None
        try:
            dados = base64.b64decode(txt)
        except Exception:
            return None
    if dados[:3] == b"\xff\xd8\xff":
        return dados, "jpg"
    if dados[:4] == b"\x89PNG":
        return dados, "png"
    if dados[:4] == b"GIF8":
        return dados, "gif"
    if dados[:4] == b"RIFF" and dados[8:12] == b"WEBP":
        return dados, "webp"
    return None


def url_foto(nome):
    arq = ligadas.get(nome)
    return f"fotos/{arq}" if arq else None


def login():
    r = requests.post(f"{AUTH}/Token", timeout=30, data={
        "grant_type": "password", "username": USER, "password": PASS, "client_id": "3"})
    if r.status_code in (400, 401):
        sys.exit(f"Login recusado pelo Ponto Web (HTTP {r.status_code}). E-mail guardado: {USER!r}; senha guardada com {len(PASS)} caracteres. "
                 "Confira se estão certos e rode de novo:  python instalar_automatico.py")
    r.raise_for_status()
    return r.json()["access_token"]


tok = login()
if not BANCO:
    b = requests.get(f"{AUTH}/ContasSecullumExterno/ListarBancos", timeout=30,
                     headers={"Authorization": f"Bearer {tok}"}).json()
    print("Bancos disponíveis:", [(x["id"], x.get("nome")) for x in b])
    BANCO = re.sub(r"[^A-Za-z0-9]", "", str(b[0]["id"]))


def call(method, path, **kw):
    global tok
    for tentativa in (1, 2):
        h = {"Authorization": f"Bearer {tok}", "secullumidbancoselecionado": str(BANCO)}
        r = requests.request(method, f"{API}/{path}", headers=h, timeout=60, **kw)
        if r.status_code == 401 and tentativa == 1:
            tok = login()  # token expirou: renova sozinho
            continue
        r.raise_for_status()
        return r.json()


def call_raw(method, path, **kw):
    """Igual a call(), mas devolve a resposta inteira (para baixar imagens)."""
    global tok
    for tentativa in (1, 2):
        h = {"Authorization": f"Bearer {tok}", "secullumidbancoselecionado": str(BANCO)}
        r = requests.request(method, f"{API}/{path}", headers=h, timeout=60, **kw)
        if r.status_code == 401 and tentativa == 1:
            tok = login()
            continue
        return r


def minutos(v):
    m = re.fullmatch(r"(-?)(\d+):(\d{2})(-?)", (v or "").strip())
    return None if not m else (-1 if (m[1] or m[4]) else 1) * (int(m[2]) * 60 + int(m[3]))


def tipo(col):
    c = col.lower()
    if "falt" in c: return "faltas"
    if "atras" in c: return "atrasos"
    if "normal" in c: return "normais"
    if c.startswith("ex") or "extra" in c: return "extras"  # Ex50%, Ex100%, ExNot...


def data_da_linha(linha, idx_data):
    """Data de uma linha do cálculo: pela coluna Data (dd/mm/aaaa) ou, se faltar, pelo campo Key."""
    val = linha.get("Value", [])
    m = re.search(r"(\d{2})/(\d{2})/(\d{4})", str(val[idx_data]) if idx_data is not None and idx_data < len(val) else "")
    if m:
        return dt.date(int(m[3]), int(m[2]), int(m[1]))
    m = re.match(r"(\d{4})-(\d{2})-(\d{2})", str(linha.get("Key", "")))
    return dt.date(int(m[1]), int(m[2]), int(m[3])) if m else None


hoje = dt.date.fromisoformat(os.environ["PAINEL_HOJE"]) if os.environ.get("PAINEL_HOJE") else dt.date.today()  # PAINEL_HOJE: só para testes
ontem = hoje - dt.timedelta(days=1)
agora = dt.datetime.now()
mes = hoje.strftime("%Y-%m")
ini_mes = hoje.replace(day=1)
fim_mes = (ini_mes + dt.timedelta(days=32)).replace(day=1) - dt.timedelta(days=1)
um_ano = hoje.replace(year=hoje.year - 1)
MESES = int(os.environ.get("MESES", "6"))  # quantos meses (contando o atual) ficam disponíveis no painel


def primeiro_dia(d, n):
    """1º dia do mês que vem n meses antes de d."""
    y, m = d.year, d.month - n
    while m <= 0:
        m += 12
        y -= 1
    return dt.date(y, m, 1)


def ultimo_dia(p):
    return (p.replace(day=28) + dt.timedelta(days=4)).replace(day=1) - dt.timedelta(days=1)


meses_lista = [primeiro_dia(hoje, i) for i in range(MESES)]  # do mês atual ao mais antigo


def fim_calculo(p):
    """Último dia considerado nos cálculos do mês p. Mês atual: só até ONTEM, porque o dia de hoje ainda não terminou
    (faltas e saldo ficariam distorcidos). Meses passados: o mês inteiro."""
    return min(ultimo_dia(p), ontem)

# 1) Funcionários
func = call("GET", "Funcionarios")

# Funcionários fora de todos os cálculos: lista EXCLUIR_PADRAO (no começo deste arquivo) + arquivo excluir.txt, se existir
ARQ_EXCLUIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "excluir.txt")
regras_excluir = list(EXCLUIR_PADRAO) + [n.strip() for n in os.environ.get("EXCLUIR_NOMES", "").split(";") if n.strip()]
if os.path.exists(ARQ_EXCLUIR):
    regras_excluir += [l.strip() for l in open(ARQ_EXCLUIR, encoding="utf-8") if l.strip() and not l.strip().startswith("#")]
for regra in dict.fromkeys(regras_excluir):
    palavras = set(norm(regra).split())
    achados = [f for f in func if palavras <= set(norm(f.get("Nome")).split())]
    if len(achados) == 1:
        func = [f for f in func if f is not achados[0]]
        print(f"Excluído dos cálculos: {achados[0].get('Nome')}  (regra: {regra!r})")
    elif achados:
        print(f"AVISO: a regra {regra!r} serve para {len(achados)} funcionários {[a.get('Nome') for a in achados]}; escreva o nome completo. Ninguém foi excluído por ela.")
    else:
        print(f"AVISO: a regra {regra!r} não casou com nenhum funcionário.")
funcionarios = [{
    "nome": f.get("Nome"), "admissao": (f.get("Admissao") or "")[:10] or None,
    "demissao": (f.get("Demissao") or "")[:10] or None,
    "departamento": f.get("DepartamentoDescricao") or "Sem departamento",
    "funcao": f.get("FuncaoDescricao")} for f in func]
ativos = [f for f in func if not f.get("Demissao") and f.get("Cpf")]

# 2) Afastamentos (12 meses atrás até 30 dias à frente)
try:
    af = call("GET", "FuncionariosAfastamentos", params={
        "dataInicio": um_ano.isoformat(), "dataFim": (hoje + dt.timedelta(days=30)).isoformat()})
except Exception as e:
    print("Afastamentos indisponíveis:", e)
    af = []
afastamentos = [{
    "inicio": (a.get("Inicio") or "")[:10], "fim": (a.get("Fim") or "")[:10],
    "justificativa": a.get("JustificativaNome") or a.get("Justificativa") or "Outros",
    "motivo": a.get("Motivo")} for a in af]

# 3) Presença de hoje: Batidas devolve uma linha por funcionário/dia (FuncionarioId + Entrada1..Saida5).
#    Presente = há ao menos um horário (HH:mm) nas colunas de entrada/saída de hoje ("Ferias" etc. não contam).
presentes, entrada1, batidas_func = None, {}, {}
bat = []
try:
    bat = call("GET", "Batidas", params={"dataInicio": hoje.isoformat(), "dataFim": hoje.isoformat()})
    com_id = {b.get("FuncionarioId") for b in bat}
    if bat and not any(f.get("Id") in com_id for f in ativos):
        print("Aviso: não consegui ligar as batidas aos funcionários (campo Id ausente em Funcionarios).")
    else:
        presentes = {b.get("FuncionarioId") for b in bat if any(
            re.search(r"\d{1,2}:\d{2}", str(v or "")) for k, v in b.items() if re.fullmatch(r"(Entrada|Saida)\d", k))}
        for b in bat:  # primeira entrada do dia, para o cálculo de atraso
            m = re.search(r"(\d{1,2}):(\d{2})", str(b.get("Entrada1") or ""))
            if m:
                entrada1[b.get("FuncionarioId")] = int(m[1]) * 60 + int(m[2])
        for b in bat:  # horários de hoje de cada funcionário (para a tabela de batidas)
            batidas_func[b.get("FuncionarioId")] = {k: str(b.get(k) or "").strip() for k in CAMPOS_BATIDA if k in b}
except Exception as e:
    print("Batidas indisponíveis:", e)
print(f"Coleta das {agora:%d/%m %H:%M} | batidas de hoje: {len(bat)} linhas lidas, "
      f"{'sem dados' if presentes is None else len(presentes)} funcionário(s) com horário registrado")

def carrega_estado():
    if NUVEM:
        if os.path.exists(ESTADO_ENC):
            try:
                return decifra(json.load(open(ESTADO_ENC)), SENHA_PAINEL)
            except Exception as e:
                print("Estado anterior ilegível (a senha mudou?); recomeçando do zero:", e)
        return {"cache": {}, "fotos": {}}
    return {"cache": json.load(open(CACHE)) if os.path.exists(CACHE) else {}, "fotos": {}}


def salva_estado(est):
    if NUVEM:
        with open(ESTADO_ENC, "w") as fh:
            json.dump(cifra(est, SENHA_PAINEL), fh)
    else:
        with open(CACHE, "w") as fh:
            json.dump(est["cache"], fh)


estado = carrega_estado()
cache = estado["cache"]


# 3b) Histórico de batidas, mês a mês. O mês atual é buscado a cada rodada; os meses passados, só 1 vez por dia.
batidas_dias = {}  # FuncionarioId -> {"aaaa-mm-dd": {campo: horário/texto}}
hist_estado = estado.setdefault("hist", {})
linhas_hist = chamadas_hist = 0
for p in meses_lista:
    ym = p.strftime("%Y-%m")
    guardado = hist_estado.get(ym)
    if p != meses_lista[0] and guardado and (agora - dt.datetime.fromisoformat(guardado["ts"])).total_seconds() < 86400:
        linhas = guardado["linhas"]
    else:
        try:
            hist = call("GET", "Batidas", params={"dataInicio": p.isoformat(), "dataFim": min(ultimo_dia(p), hoje).isoformat()})
        except Exception as e:
            print(f"Histórico de batidas de {ym} indisponível:", e)
            linhas = guardado["linhas"] if guardado else []
        else:
            chamadas_hist += 1
            linhas = []
            for b in hist:
                d = str(b.get("Data") or "")[:10]
                campos = {k: str(b.get(k) or "").strip() for k in CAMPOS_BATIDA if str(b.get(k) or "").strip()}
                if d and campos:
                    linhas.append([b.get("FuncionarioId"), d, campos])
            hist_estado[ym] = {"ts": agora.isoformat(), "linhas": linhas}
    linhas_hist += len(linhas)
    for fid, d, campos in linhas:
        batidas_dias.setdefault(fid, {})[d] = campos
print(f"Histórico de batidas: {linhas_hist} linhas em {MESES} mês(es) ({chamadas_hist} consulta(s) à API)")

# 4) Cálculos por funcionário ativo e por mês (cache + limite de chamadas por hora)
chave = lambda f: f"{f['Cpf']}|{mes}"  # mês atual
chave_m = lambda f, ym: f"{f['Cpf']}|{ym}"


def diagnostico(f, cols, r):
    """Mostra todas as colunas do cálculo de um funcionário e quais valem o saldo que o sistema exibe."""
    print(f"\n=== DIAGNÓSTICO: {f.get('Nome')} (mês {mes}) ===")
    tot = {c: v for c, v in zip(cols, r.get("Totais", [])) if v}
    ult = {}
    for l in r.get("Linhas", []):
        for c, v in zip(cols, l.get("Value", [])):
            if v and c != "Data" and minutos(v) is not None:
                ult[c] = v
    print("Totais do mês:", tot)
    print("Último valor diário (colunas com valor):", ult)
    if SALDO_ESPERADO:
        alvo = minutos(SALDO_ESPERADO if ":" in SALDO_ESPERADO else SALDO_ESPERADO + ":00")
        ach = [c + " (totais)" for c, v in tot.items() if minutos(v) is not None and abs(minutos(v)) == abs(alvo)]
        ach += [c + " (último dia)" for c, v in ult.items() if abs(minutos(v)) == abs(alvo)]
        print(f"Colunas que valem {SALDO_ESPERADO}:", ach or "nenhuma")
    print("=== fim do diagnóstico ===\n")


def desatualizado(c, atual, f=None, p=None):
    if atual and DIAG and f is not None and DIAG in norm(f.get("Nome")):
        return True  # investigando este funcionário: sempre refaz
    if c.get("x", {}).get("sig", "BSaldo|total") != SIG_SALDO:
        return True
    if not c.get("ts") or "extras_dia" not in c.get("x", {}):
        return True
    if c.get("x", {}).get("ate") != fim_calculo(p or meses_lista[0]).isoformat():
        return True  # virou o dia (ou o mês): o cálculo passa a incluir o que acabou de fechar
    idade = (agora - dt.datetime.fromisoformat(c["ts"])).total_seconds()
    return idade >= (3000 if atual else 86400)  # mês atual: ~50 min; meses passados: 1 dia


tarefas = []
for p in meses_lista:
    for f in ativos:
        c = cache.get(chave_m(f, p.strftime("%Y-%m")), {})
        if desatualizado(c, p == meses_lista[0], f, p):
            tarefas.append((p != meses_lista[0], c.get("ts", ""), f, p))
tarefas.sort(key=lambda t: (t[0], t[1]))  # mês atual primeiro; em cada grupo, os mais antigos primeiro
feitas, vistas = 0, False
for _, _, f, p in tarefas[:MAX_CALC]:
    ym = p.strftime("%Y-%m")
    fim = fim_calculo(p)
    if fim < p:  # 1º dia do mês: ainda não há nenhum dia fechado neste mês
        cache[chave_m(f, ym)] = {"d": hoje.isoformat(), "ts": agora.isoformat(), "dep": f.get("DepartamentoDescricao") or "Sem departamento",
                                 "nome": f.get("Nome"), "t": {}, "x": {"extras": 0, "atrasos": 0, "normais": 0, "faltas": 0, "faltas_dias": 0,
                                 "faltou_hoje": False, "sig": SIG_SALDO, "ate": fim.isoformat(), "saldo": 0, "extras_dia": [0] * 7}}
        continue
    try:
        r = call("POST", "Calcular", json={
            "FuncionarioCpf": f["Cpf"], "DataInicial": p.isoformat(), "DataFinal": fim.isoformat()})
        cols = r.get("Colunas", [])
        if not vistas:
            print("Colunas do cálculo:", cols)
            print("Totais do primeiro funcionário:", {k: v for k, v in zip(cols, r.get("Totais", [])) if v})
            vistas = True
        tot = {}
        x = {"extras": 0, "atrasos": 0, "normais": 0, "faltas": 0, "faltas_dias": 0, "faltou_hoje": False}
        for col, val in zip(cols, r.get("Totais", [])):
            m = minutos(val)
            if m is not None:
                tot[col] = m
                t = tipo(col)
                if t:
                    x[t] += m  # extras, atrasos, normais e faltas (em minutos)
        x["sig"] = SIG_SALDO
        x["ate"] = fim.isoformat()
        x["saldo"] = tot.get(COLUNA_SALDO)  # modo "total" (coluna do relatório); None se não existir/vier vazia
        if SALDO_MODO == "calculado":  # horas extras - horas de falta (e - atrasos, se SALDO_ATRASOS=1)
            x["saldo"] = x["extras"] - x["faltas"] - (x["atrasos"] if SALDO_ATRASOS else 0)
        elif SALDO_MODO == "ultimo" and COLUNA_SALDO in cols:
            i_s = cols.index(COLUNA_SALDO)
            vals = [minutos(l.get("Value", [])[i_s]) for l in r.get("Linhas", []) if i_s < len(l.get("Value", []))]
            vals = [v for v in vals if v is not None]
            x["saldo"] = vals[-1] if vals else None
        if DIAG and DIAG in norm(f.get("Nome")) and ym == mes:
            diagnostico(f, cols, r)
        idx_f = [i for i, col in enumerate(cols) if tipo(col) == "faltas"]
        idx_e = [i for i, col in enumerate(cols) if tipo(col) == "extras"]
        idx_d = cols.index("Data") if "Data" in cols else None
        x["extras_dia"] = [0] * 7  # minutos de hora extra por dia da semana (0 = domingo ... 6 = sábado)
        for linha in r.get("Linhas", []):
            val = linha.get("Value", [])
            dia_ = data_da_linha(linha, idx_d)
            if dia_:
                x["extras_dia"][(dia_.weekday() + 1) % 7] += sum(minutos(val[i]) or 0 for i in idx_e if i < len(val))
            if any((minutos(val[i]) or 0) > 0 for i in idx_f if i < len(val)):
                x["faltas_dias"] += 1
                if str(linha.get("Key", ""))[:10] == hoje.isoformat():
                    x["faltou_hoje"] = True
        cache[chave_m(f, ym)] = {"d": hoje.isoformat(), "ts": agora.isoformat(), "dep": f.get("DepartamentoDescricao") or "Sem departamento",
                                 "nome": f.get("Nome"), "t": tot, "x": x}
        feitas += 1
    except Exception as e:
        print("Falha no cálculo de um funcionário:", e)
if len(tarefas) > MAX_CALC:
    print(f"{len(tarefas) - MAX_CALC} cálculo(s) ficam para a próxima rodada (limite de {MAX_CALC} por rodada)")
salva_estado(estado)

por_dep = defaultdict(lambda: defaultdict(int))
colaboradores, processados, usados = [], 0, set()
difer = 0
for f in ativos:
    c = cache.get(chave(f))
    if not c:
        continue
    processados += 1
    for col, m in c["t"].items():
        por_dep[c["dep"]][col] += m
    x = c.get("x", {})
    h = entrada1.get(f.get("Id"))
    chave_v = acha_valor(c["nome"])
    taxa = VALORES.get(chave_v)
    if chave_v:
        usados.add(chave_v)
    ed = x.get("extras_dia") or [0] * 7
    if sum(ed) != x.get("extras", 0):
        difer += 1
    atrasado = h is not None and h > LIMITE_ENTRADA + TOLERANCIA
    meses = {}
    for p in meses_lista:
        cm = cache.get(chave_m(f, p.strftime("%Y-%m")))
        if cm:
            em = cm.get("x", {}).get("extras", 0)
            meses[p.strftime("%Y-%m")] = {"extras": em, "a_pagar": None if taxa is None else round(em / 60 * taxa, 2), "saldo": cm.get("x", {}).get("saldo"), "faltas": cm.get("x", {}).get("faltas", 0)}
    colaboradores.append({
        "nome": c["nome"], "departamento": c["dep"],
        "presente": None if presentes is None else (f.get("Id") in presentes),
        "entrada_hoje": None if h is None else f"{h // 60:02d}:{h % 60:02d}",
        "atrasado_hoje": atrasado, "atraso_min": h - LIMITE_ENTRADA - TOLERANCIA if atrasado else 0,
        "faltou_hoje": bool(x.get("faltou_hoje")) and c["d"] == hoje.isoformat(),
        "extras": x.get("extras", 0), "faltas": x.get("faltas", 0), "extras_dia": ed, "meses": meses,
        "a_pagar_dia": None if taxa is None else [round(m / 60 * taxa, 2) for m in ed], "a_pagar": None if taxa is None else round(x.get("extras", 0) / 60 * taxa, 2),
        "saldo": x.get("saldo"), "atrasos": x.get("atrasos", 0),
        "normais": x.get("normais", 0), "faltas_dias": x.get("faltas_dias", 0)})

print("\nHoras extras e valor a pagar por funcionário:")
for z in sorted(colaboradores, key=lambda z: -z["extras"]):
    valor = "SEM VALOR/HORA" if z["a_pagar"] is None else "R$ %.2f" % z["a_pagar"]
    fh = lambda m: ("-" if (m or 0) < 0 else "") + f"{abs(m or 0) // 60}h{abs(m or 0) % 60:02d}"
    print(f'  {z["nome"][:36]:36} extras {fh(z["extras"]):>7} | falta {fh(z["faltas"]):>7} | saldo {fh(z["saldo"]):>8} | {valor}')
print("  Total a pagar: R$ %.2f" % sum(z["a_pagar"] or 0 for z in colaboradores))
if colaboradores and not any(z["extras"] for z in colaboradores):
    print("AVISO: nenhuma hora extra encontrada. Confira os nomes das colunas do cálculo impressos acima.")
sem_valor = [c["nome"] for c in colaboradores if c["a_pagar"] is None]
if sem_valor:
    print("Sem valor da hora cadastrado (fora do total a pagar):", sem_valor)
sobra = [k for k in VALORES if k not in usados]
if sobra:
    print("Nomes de valores_hora.json sem funcionário correspondente (confira a grafia):", sobra)

# 5) Fotos
if NUVEM:
    # na nuvem as fotos NÃO ficam em arquivos: vão reduzidas, dentro dos dados criptografados
    fotos_nuvem = estado.setdefault("fotos", {})
    fotos_sem = estado.setdefault("fotos_sem", {})  # quem não tem foto cadastrada: tenta de novo só 1 vez por dia
    baixadas = falhas = 0
    for f in func:
        chave_f = norm(f.get("Nome"))
        if f.get("Demissao") or not f.get("Id") or (chave_f in fotos_nuvem and not ATUALIZAR_FOTOS):
            continue
        if chave_f in fotos_sem and (agora - dt.datetime.fromisoformat(fotos_sem[chave_f])).total_seconds() < 86400:
            continue
        if baixadas >= MAX_FOTOS or falhas >= 3:
            break
        try:
            img = extrai_imagem(call_raw("GET", "Funcionarios/fotos", params={"funcionarioId": f["Id"]}))
        except Exception as e:
            falhas += 1
            print("Foto indisponível:", e)
            continue
        mini = miniatura(img[0]) if img else None
        if mini:
            fotos_nuvem[chave_f] = mini
            baixadas += 1
        else:
            fotos_sem[chave_f] = agora.isoformat()
    n_ativos = [f for f in func if not f.get("Demissao")]
    print(f"Fotos: {sum(1 for f in n_ativos if norm(f.get('Nome')) in fotos_nuvem)} de {len(n_ativos)} funcionários ativos com foto ({baixadas} baixadas agora)")

    def url_foto(nome):
        return fotos_nuvem.get(norm(nome))
else:
    # 5) Fotos: usa as que já estão na pasta "fotos" e baixa da API as que faltam
    os.makedirs(PASTA_FOTOS, exist_ok=True)
    print("Pasta de fotos:", PASTA_FOTOS)
    fotos_arq = indexa_fotos()
    nomes_ativos = [f.get("Nome") for f in func if not f.get("Demissao")]
    ligadas = liga_fotos(nomes_ativos, fotos_arq)
    baixadas = falhas = 0
    for f in func:
        if f.get("Demissao") or not f.get("Id"):
            continue
        if f.get("Nome") in ligadas and not ATUALIZAR_FOTOS:
            continue
        if baixadas >= MAX_FOTOS or falhas >= 3:
            break
        try:
            img = extrai_imagem(call_raw("GET", "Funcionarios/fotos", params={"funcionarioId": f["Id"]}))
        except Exception as e:
            falhas += 1
            print("Foto indisponível:", e)
            continue
        if img:
            arq = f"{nome_arquivo(f.get('Nome'))}.{img[1]}"
            with open(os.path.join(PASTA_FOTOS, arq), "wb") as fh:
                fh.write(img[0])
            fotos_arq[norm(f.get("Nome"))] = arq
            ligadas[f.get("Nome")] = arq
            baixadas += 1
    print(f"Fotos: {len(fotos_arq)} arquivo(s) na pasta | {len(ligadas)} de {len(nomes_ativos)} funcionários ativos com foto ({baixadas} baixadas agora)")
    sem_foto = [n for n in nomes_ativos if n not in ligadas]
    if sem_foto:
        print("Funcionários sem foto:", sem_foto[:25])
    orfas = [a for a in fotos_arq.values() if a not in set(ligadas.values())]
    if orfas:
        print("Arquivos da pasta que não casaram com nenhum funcionário (confira o nome):", orfas[:25])


def dias_de(f):
    dias = dict(batidas_dias.get(f.get("Id"), {}))
    de_hoje = {k: v for k, v in batidas_func.get(f.get("Id"), {}).items() if v}
    if de_hoje:
        dias[hoje.isoformat()] = de_hoje
    return dias


batidas_hoje = [{"nome": f.get("Nome"), "departamento": f.get("DepartamentoDescricao") or "Sem departamento",
                 "dias": dias_de(f), "foto": url_foto(f.get("Nome"))} for f in func if not f.get("Demissao")]

saida = {
    "gerado_em": dt.datetime.now().astimezone().isoformat(timespec="minutes"),
    "intervalo_min": int(os.environ.get("INTERVALO_MIN", "30")),
    "calculo_ate": fim_calculo(meses_lista[0]).isoformat(),  # horas, faltas e saldo do mês atual valem até este dia
    "funcionarios": funcionarios, "afastamentos": afastamentos, "colaboradores": colaboradores, "batidas": batidas_hoje,
    "regra": {"entrada": f"{LIMITE_ENTRADA // 60:02d}:{LIMITE_ENTRADA % 60:02d}", "tolerancia": TOLERANCIA},
    "calculos": {"mes": mes, "processados": processados, "total": len(ativos),
                 "por_departamento": {d: dict(v) for d, v in por_dep.items()}},
}
salva_estado(estado)
if NUVEM:
    os.makedirs(os.path.dirname(OUT_ENC) or ".", exist_ok=True)
    with open(OUT_ENC, "w") as fh:
        json.dump(cifra(saida, SENHA_PAINEL), fh)
    print(f"Dados criptografados em {OUT_ENC}")
else:
    with open(OUT, "w", encoding="utf-8") as fh:
        json.dump(saida, fh, ensure_ascii=False)
print(f"OK: {len(funcionarios)} funcionários, {len(afastamentos)} afastamentos, "
      f"cálculos {processados}/{len(ativos)} ({feitas} chamadas nesta rodada)")
