# Users Service
 Users Service é uma API desenvolvida para fazer o gerenciamento de usuário, onde o usuário pode se registrar, fazer login e atualizar a senha.

<br>

## Como utilizar a aplicação
- Primeiro crie o arquivo .env, utilize o as chaves disponibilizadas .env.example.
- Chaves utilizadas em .env.example:
  - PORT: Porta que irá rodar a aplicação (porta padrão é3000)
  - SECRETKEY: Uma senha para ser utilizada na validação do token
  - EXPIRESIN: Tempo até expirar o token, valores apenas em números será interpretado como milisegundos, valores em string aceitos { h: hora, m: minutos, s: segundos }. Exemplo de string recebido: 1h
- Próximo e ultimo passo rodar seguite comando no terminal: ```yarn dev```


### End-Points

1 -  Registrar usuário: `/signup` <br>
2 -  Fazer login: `/login` <br>
3 -  Retornar todos usuário cadastrados: `/users` <br>
4 -  Atualizar senha: `/users/:uuid/password` <br>

<br>

---

## Cadastrar usuário

|   url    | metodo | status |
| :------: | :----: | :----: |
| `/signup` | `Post` | `201`  |

**Body** - `json`
```
{
	"username": "John Doe",
	"email": "johndoe@email.com",
	"age": 18,
	"password": "senha_forte"
}
```
<br>

*Retorno esperado*:   `201 - created`
```
{
	"uuid": "65de3705-be0c-49eb-a03b-3bdeef20ae4a",
	"username": "John Doe",
	"age": 18,
	"email": "johndoe@email.com",
	"createdOn": "Mon Mar 28 2022 12:25:41 GMT-0300"
}
```
<br>

**Erros de cadastro:**

*Envio de `json` faltando uma chave:*
<br>

**Body** 
```
{
	"email": "johndoe@email.com",
	"age": 18,
	"password": "senha_forte"
}
```
*Retorno esperado:* `422 - Unprocessable Entity` - 
```
{
	"error": [
		"username is a required field"
	]
}
```

*Cadastrar usuário já existente:*
<br>

**Body** 
```
{
	"email": "johndoe@email.com",
	"age": 18,
	"password": "senha_forte"
}
```
*Retorno esperado:* `409 - Conflict` - 
```
{
	"error": "email already exists"
}
```

---

## Login
  
|   url    | metodo | status |
| :------: | :----: | :----: |
| `/login` | `Post` | `201`  |

**Body** - `json`
```
{
	"username": "John Doe",
	"email": "johndoe@email.com",
	"password": "senha_forte"
}
```
*Retorno esperado:* `200 - OK` - 
```
{
	"accessToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJlbWFpbCI6InRlc3RlQGVtYWwuY29tIiwidXNlcm5hbWUiOiJ0ZXN0ZSIsInBhc3N3b3JkIjoiMTIzIiwiaWF0IjoxNjQ4NDgyNzQ3LCJleHAiOjE2NDg0ODYzNDd9.sa6uXLVEBc5O0lyUW1t_uzqXWHu--rKOrGYGZZzr9oI"
}
```

<br>

**Erros de login:**

*Envio de `json` faltando uma chave:*
<br>

**Body** 
```
{
	"email": "johndoe@email.com",
	"password": "senha_forte"
}
```
*Retorno esperado:* `422 - Unprocessable Entity` - 
```
{
	"error": [
		"username is a required field"
	]
}
```

*Login `json` com senha errada:*
<br>

**Body** 
```
	"username": "John Doe",
	"email": "johndoe@email.com",
	"password": "senha_fraca"
```
*Retorno esperado:* `400 - Bad Request` - 
```
{
	"message": "Invalid password"
}
```

---

# Get users
  Para ter acesso a essa rota o usuário precisa estar logado e ter um token válido

|   url    | metodo | status |
| :------: | :----: | :----: |
| `/users` | `GET` | `200`  |

*Retorno esperado:* `200 - OK`
```
[
	{
		"uuid": "1bebb243-a766-45d7-af76-06e9a47e70d4",
		"username": "John Doe",
		"age": 18,
		"email": "johndoe@email.com",
		"password": "$2b$10$qKDQ3J5vcD.YiUHPixYDpezdpBM9JkN1FZ7TkmbQSgWblT.9GUyZu",
		"createdOn": "Mon Mar 28 2022 12:59:49 GMT-0300 (Horário Padrão de Brasília)"
	},
	{
		"uuid": "2326b16b-0cfb-4d8e-b05b-8e6d352f0755",
		"username": "Doe John",
		"age": 18,
		"email": "doejohne@email.com",
		"password": "$2b$10$eHneDP6hMT1pCBewv.GnG.VWyUPZ6mcWzDu.5VJqu57pHtQzmSb1m",
		"createdOn": "Mon Mar 28 2022 13:00:05 GMT-0300 (Horário Padrão de Brasília)"
	}
]
```

---

## Mudar senha
  Para ter acesso a essa rota o usuário precisa estar logado e ter um token válido. Não é possível alterar a senha de outro usuário.

|           url   					| metodo | status |
|         :------:					| :----: | :----: |
| `/users/:userId/password` | `PUT`  | `204`  |

**Body** - `json`
```
{
	"password": "nova_senha_forte"
}
```


**Erros de update:**

*Informando um userId inexistente:*

*Retorno esperado:* `404 - Not Found`
```
{
	"error": "user not found"
}
```

*Envio de `json` com chave errada:*

**Body**
```
{
	"word": "qerjmẃerkmhnkpwrenṕMWEǴIONPE"
}
```

*Retorno esperado:* `422 - Unprocessable Entity`

```
{
	"error": [
		"password is a required field"
	]
}
```


*Alterar a senha de um outro usuário:*

*Retorno esperado:* `403 - Forbidden`

```
{
	"error": "unauthorazed, you can only change your password"
}
```