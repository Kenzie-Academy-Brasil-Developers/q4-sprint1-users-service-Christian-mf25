### End-Points

1. /signup
2. /login
3. /users
4. /users/:uuid/password

* Cadastrar usuário

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

* Login
  
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

* Get users
  Para ter acesso a essa rota o usuário precisa estar logado e ter um token válido

|   url    | metodo | status |
| :------: | :----: | :----: |
| `/users` | `GET` | `200`  |


* Mudar senha
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