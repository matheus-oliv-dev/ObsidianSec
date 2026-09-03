# Segurança e capacidade do MVP

Revisão técnica realizada em 13 de agosto de 2026.

## Estado atual medido

- Supabase no plano Free, projeto ativo e PostgreSQL 17.
- Banco de dados: aproximadamente 11 MB usados de 500 MB (2,2%).
- Storage: 39.754.499 bytes usados (aproximadamente 38 MB) em 6 objetos.
- Biblioteca: 2 clipes, ambos ativos.
- Salas no momento da medição: 5 salas e 8 associações de jogadores.
- Limite do jogo: 8 jogadores por sala e até 8 rodadas.

Vídeos ficam no Storage, não no espaço de 500 MB do banco. Com a média atual de
aproximadamente 19,9 MB por clipe completo (original, versão sem diálogo e
eventuais anexos), 1 GB comporta aproximadamente 50 clipes no total. Como já há
2, a estimativa conservadora é de mais 48 clipes semelhantes. Se cada clipe usar
dois vídeos no limite de 50 MB, restam aproximadamente 9 clipes completos.
Gravações temporárias dos jogadores também consomem esse mesmo 1 GB e são
apagadas quando a sala expira.

## Correções implementadas

- Senha opcional de 4 a 64 caracteres por sala, armazenada somente como hash
  `scrypt` com sal aleatório e comparação em tempo constante.
- Limitação atômica de tentativas por usuário e por rede para criação, entrada,
  leitura, ações, uploads e transcrição.
- Estado completo da sala removido do acesso direto e do Realtime do cliente.
  O navegador recebe somente uma projeção autorizada e um evento de revisão.
- Autoria das dublagens, votos e notas ficam ocultos até a tela de resultado.
- Chaves de Storage nunca são retornadas ao navegador; são usadas URLs assinadas
  curtas e apenas para as mídias necessárias à etapa atual.
- Bucket separado de 5 MB para gravações e limite de 50 MB por vídeo no plano
  Free.
- Presença por heartbeat, remoção de conexões abandonadas e transferência de
  host.
- Limite de corpo JSON, validação Zod, normalização de apelidos e remoção de
  controles Unicode potencialmente enganosos.
- Cabeçalhos CSP, HSTS, anti-iframe, anti-MIME-sniffing e política de origem.
- Acesso direto às tabelas editoriais e legadas revogado para usuários do jogo;
  rotas administrativas continuam validadas no servidor.
- Índices adicionados às chaves estrangeiras indicadas pelo advisor do Supabase.
- Limpeza diária de salas, gravações e registros antigos do limitador.

## Capacidade recomendada antes de um teste de carga

> **Desatualizado.** Esta seção foi escrita para o plano Free. O cálculo atual,
> para Supabase Pro + Vercel Pro + Bunny.net, está em
> [`capacidade-simultaneos.md`](./capacidade-simultaneos.md).

O limite oficial do Realtime Free é 200 conexões simultâneas. Como cada jogador
mantém uma conexão, o teto teórico é de 25 salas lotadas. Esse número não é uma
garantia de desempenho: API serverless, assinatura de mídias, egress, navegador e
limites da hospedagem também participam.

Para o primeiro lançamento, use como limite operacional 80 a 120 jogadores
simultâneos (10 a 15 salas lotadas). Antes de liberar mais, execute um teste de
carga em staging com 25, 50, 100, 150 e 200 jogadores e acompanhe latência p95,
erros 429/5xx, conexões Realtime, CPU/memória do banco, egress e Storage.

O volume de votos cresce de forma quadrática. Com 8 jogadores são no máximo 56
notas por rodada, ainda adequado ao estado atual. Não aumente o limite de 8 sem
normalizar salas, envios e votos em tabelas transacionais e testar concorrência.

## Caminho de escala

1. Instrumentar erros, latência e funil da partida; configurar alertas de uso no
   Supabase e na hospedagem.
2. Executar teste de carga reproduzindo uma partida inteira, não apenas leituras.
3. Migrar para Supabase Pro antes de exceder os limites Free: 100 GB de Storage,
   250 GB de egress e 500 conexões Realtime incluídas.
4. Para milhares de jogadores, normalizar o JSON de `live_rooms`, mover ações
   críticas para funções SQL transacionais e usar broadcast/presença do Realtime
   para reduzir polling.
5. Processamento de vídeo/transcrição deve ir para fila e workers separados; as
   rotas web apenas criam e consultam jobs.
6. Definir retenção curta para dublagens, expurgar usuários anônimos inativos e
   mover mídia pública de alto tráfego para uma estratégia de CDN apropriada.

## Pendências externas antes de produção

- Aplicar `supabase/migrations/202608130006_security_hardening.sql`.
- Configurar `RATE_LIMIT_SECRET` aleatório e diferente das chaves do Supabase.
- Configurar `CRON_SECRET` e confirmar a execução diária do cron.
- Ativar Cloudflare Turnstile ou hCaptcha no login anônimo; o próprio Supabase
  recomenda CAPTCHA para evitar abuso e crescimento artificial de MAU.
- Rotacionar as chaves privadas que já foram compartilhadas em conversas ou
  capturas e atualizar somente os segredos do ambiente de produção.
- Realizar teste multiplayer em pelo menos Chrome, Edge, Firefox, Safari e dois
  celulares reais.

## Referências oficiais

- [Preços e cotas do Supabase](https://supabase.com/pricing)
- [Tamanho do banco](https://supabase.com/docs/guides/platform/database-size)
- [Compute e conexões](https://supabase.com/docs/guides/platform/compute-and-disk)
- [Limites do Realtime](https://supabase.com/docs/guides/realtime/limits)
- [Limites de upload do Storage](https://supabase.com/docs/guides/storage/uploads/file-limits)
- [Autenticação anônima](https://supabase.com/docs/guides/auth/auth-anonymous)
- [RLS](https://supabase.com/docs/guides/database/postgres/row-level-security)


---
*Documentação integrada da suíte ChimeraGuard DevSecOps.*
