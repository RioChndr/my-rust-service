# Rust service Exercise

This Rust service will create server to serve some API. Our target are to create basic service that used in production.

- Authentication
  - Register
  - Login
- public API
- private API

## Requirement

### Authentication Requirement

- `POST     /auth/login` Return user information
- `POST     /auth/register` Register new user
- `POST     /auth/me` get user information

### Public API

- `GET      /public/ip` return user ip
- `GET      /public/all` return all request information
- `GET      /public/method` return data from query/body
- `POST     /public/method` return data from query/body
- `PUT      /public/method` return data from query/body
- `DELETE   /public/method` return data from query/body

### Table Database

#### Table : User

| field     | type   |
| --------- | ------ |
| id        | uuid   |
| email     | string |
| password  | string |
| createdAt | string |

## Debug

### Use `entr`

[entr](https://github.com/eradman/entr)

```sh
find src | entr -rc cargo run
```

### Use Cargo watch

[Cargo watch](https://github.com/watchexec/cargo-watch)

```sh
# install

$ cargo install cargo-watch

# Run run with arguments
$ cargo watch -x 'run -- --some-arg'
```


## Test

```sh
curl -X POST http://localhost:3000/auth/login --json '{
  "email": "email@email.com",
  "password": "password123"
}' | jq
```

```sh
curl --get http://localhost:3000/auth/me -H 'Authorization: Bearer ...' | jq
```

# Key

JWT require RSA key

**Generate secret key**
```sh
openssl genrsa -out keypair.pem 2048
```

**Generate public key**
```sh
openssl rsa -in keypair.pem -pubout -out publickey.crt
```