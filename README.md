# Logon System

Aplicação Node.js para estudar **autenticação web, sessões e controles básicos de AppSec**.

O projeto mantém o escopo pequeno de propósito: um fluxo de login completo, com validação, sessão, persistência local e controles que normalmente ficam esquecidos em exemplos simples de autenticação.

## Stack

- Node.js 22+
- Express 5
- SQLite com `better-sqlite3`
- `express-rate-limit`
- Helmet
- Node Test Runner

## Controles estudados

- validação de login
- proteção contra brute force
- resistência a account enumeration
- criação e expiração de sessão
- cookies de sessão
- logout
- headers de segurança
- configuração por ambiente
- audit logging
- testes de autenticação

## Rodando localmente

```bash
npm install
npm run dev
```

Para execução normal:

```bash
npm start
```

Testes e validações:

```bash
npm test
npm run check
```

## Estrutura

- `src/` — servidor, aplicação e controles de segurança
- `public/` — interface
- `test/` — testes
- `.env.example` — referência de configuração
- `docs/` — documentação de autenticação

## Segurança

O repositório não deve conter senhas, tokens, cookies de sessão ou dados reais. Os exemplos existem apenas para estudo local.
