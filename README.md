# Painel de RH

Painel que busca os dados no Ponto Web a cada 30 minutos e publica uma página protegida por senha.
Os dados ficam **criptografados** no site; e-mail, senha do Ponto Web, valores por hora e exclusões ficam nos *Secrets* do repositório (Settings > Secrets and variables > Actions).

Secrets usados: SECULLUM_USER, SECULLUM_PASS, PAINEL_SENHA (mínimo 12 caracteres), VALORES_HORA (JSON), EXCLUIR_NOMES (nomes separados por ponto e vírgula).
