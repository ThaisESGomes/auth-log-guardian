# Auth Log Guardian

Programa em Python para analisar logs de autenticação SSH. Ele procura tentativas de login repetidas e logins aceitos depois de várias falhas, mostrando as linhas do log que geraram cada alerta.

A ideia é facilitar a leitura desses registros e estudar como detectar comportamentos suspeitos. Um alerta não significa que houve uma invasão: é preciso conferir o contexto.

## Como executar

Requer Python 3.11 ou superior, sem instalar bibliotecas adicionais.

```bash
git clone https://github.com/ThaisESGomes/auth-log-guardian.git
cd auth-log-guardian
python guardian.py examples/auth.log --config config.toml
```

O arquivo de exemplo tem dados fictícios. A execução deve encontrar oito eventos e gerar dois alertas: falhas repetidas e um login aceito após as falhas.

Para salvar o resultado em Markdown:

```bash
python guardian.py examples/auth.log --config config.toml --format markdown --output report.md
```

O formato padrão é JSON. Há exemplos dos resultados em [report.json](examples/report.json) e [report.md](examples/report.md).

Para logs no formato syslog, que não incluem o ano, informe-o na execução:

```bash
python guardian.py /caminho/auth.log --year 2026 --config config.toml
```

## Configuração

O arquivo `config.toml` define quantas falhas geram um alerta, o intervalo de tempo e os IPs ou redes ignorados:

```toml
threshold = 5
window_seconds = 120
allowlist = ["127.0.0.0/8", "::1/128"]
```

Nesse exemplo, cinco falhas do mesmo IP dentro de 120 segundos geram um alerta. Para relacionar as falhas a um login aceito, o usuário também precisa ser o mesmo.

## Testes

```bash
python -m unittest discover -s tests -v
```

Os 12 testes verificam as regras, os limites da janela de tempo, IPv6, exclusões, entradas inválidas e outros casos. Também são executados pelo GitHub Actions em Python 3.11, 3.12 e 3.13.

## Limitações

- Reconhece mensagens OpenSSH `Failed` e `Accepted`. Outros formatos podem ser ignorados.
- Horários sem fuso são tratados como UTC. Logs syslog precisam do ano correto e devem ser separados se cruzarem a virada do ano.
- Carrega os eventos em memória para ordená-los. Não acompanha o log em tempo real.
- Pode gerar alertas para erros legítimos de senha e não detecta todos os tipos de ataque.
- Não bloqueia IPs nem confirma invasões. As linhas indicadas servem como ponto de partida para uma análise.
- Remova dados sensíveis antes de compartilhar logs reais.

Licença [MIT](LICENSE).
