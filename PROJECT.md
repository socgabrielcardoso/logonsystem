# Logon System — notas do projeto

## Finalidade

Aplicação pequena para estudar autenticação web sem esconder a parte de segurança atrás de frameworks maiores.

## Componentes

- Express 5;
- SQLite;
- sessão e cookies;
- rate limiting;
- headers com Helmet;
- configuração por ambiente;
- testes com Node Test Runner.

## Pontos de atenção

O projeto trata login como uma fronteira de segurança. Isso inclui não só validar usuário e senha, mas também controlar tentativa repetida, sessão, logout, mensagens de erro, configuração e registro de eventos.

## Escopo

Estudo local de Authentication e Application Security.
