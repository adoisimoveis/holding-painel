# Painel da Holding

App web instalável (PWA) para operar a Holding de Agentes pelo celular: carteiras, gráficos, propostas,
banca de investimentos, relatórios, histórico e freio de emergência.

**Este repositório só tem o código do app. Nenhum dado, saldo, senha ou chave fica aqui.** Os dados são
lidos do repositório privado do sistema, com uma chave que existe apenas no celular do dono.

## Segurança

- Chave do GitHub *fine-grained*, restrita ao repositório privado: Contents **leitura**, Issues **leitura e
  escrita**, Actions **leitura e escrita**. Ela não consegue alterar código nem configuração.
- A chave do GitHub e a chave de assinatura ficam criptografadas no aparelho (AES-GCM 256; chave derivada
  do PIN com PBKDF2-SHA256, 310 mil iterações). Cinco PINs errados apagam o cofre.
- Bloqueio automático após 5 minutos parado ou 1 minuto fora do app.
- Cada operação é uma issue privada com o comando assinado (HMAC-SHA256). O robô aceita só assinatura
  válida, do autor autorizado, em até 30 minutos e sem repetição; o resto é rejeitado com alarme.
- Operações pedem o PIN de novo, ou a digital (passkey com a extensão PRF: a digital gera a chave de um segundo
  cofre; sem PRF no aparelho, a digital não é oferecida e nada fica guardado aberto).
- Print do banco: o Android entrega a imagem ao Painel ("Compartilhar"); ela é reduzida, enviada em pedaços
  assinados pelo hash e apagada do GitHub depois da leitura. A carteira só muda quando o dono confere e aplica.
- Desfazer: o último registro pode ser desfeito por 10 minutos.
- Política de segurança de conteúdo: o app só carrega os próprios arquivos e só conversa com api.github.com.
  Sem bibliotecas de terceiros. Todo texto vindo do repositório é escapado.

## Instalar no Android

1. Abra o endereço do app no Chrome.
2. Menu ⋮ → **Adicionar à tela inicial** (ou **Instalar app**).
3. Na primeira abertura: copie a chave de assinatura para o segredo `PAINEL_CHAVE` do repositório
   privado, cole a chave do GitHub e crie o PIN.

## Arquivos

| Arquivo | Função |
| --- | --- |
| `index.html` | Casca e política de segurança |
| `app.js` | Cofre do PIN e da digital, API do GitHub, comandos assinados, telas Hoje · Carteira · Análises · Ajustes |
| `app.css` | Visual (tema claro e escuro) |
| `sw.js` | Guarda só a casca para abrir rápido; recebe o print compartilhado; nunca guarda dados do GitHub |
| `manifest.webmanifest`, `icone*` | Instalação como app |
