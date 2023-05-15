# OpenID Connect サンプルアプリ
OpenID Connect の説明のためのサンプルアプリです。

app/lib/google_auth.rb を書き換えると、攻撃対策の切り替え(state, nonce, PKCE)ができます。

## 実行方法

```
cp .env.example .env
# .env にGCPで得たクライアントIDやクライアントシークレットを設定します
bundle install
bundle exec rails s
```

ブラウザで http://localhost:3000 を開いてください。
