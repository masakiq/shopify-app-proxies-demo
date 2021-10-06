# gem

```sh
gem install sinatra
gem install httparty
gem install jwt
```

## generate HS512 HMAC_SECRET_KEY

```sh
openssl rand -base64 172 | tr -d '\n'
```

# set env

```sh
export SHOPIFY_APP_API_KEY=
export SHOPIFY_APP_API_SECRET_KEY=
export SHOPIFY_APP_BASE_URL=
export SHOPIFY_APP_HMAC_SECRET_KEY=
```

# run

```sh
ruby main.rb
```

```sh
ngrok http http://127.0.0.1:4567
```

# access

https://yourshop.myshopify.com/apps/proxy/account
