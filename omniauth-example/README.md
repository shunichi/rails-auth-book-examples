# omniauth-google-oauth2 を使ったGoogleログインのサンプルアプリ
書籍では説明していませんが、gemを使ってGoogleログインを実装するサンプルです。

## 実行方法

```
cp .env.example .env
# .env にGCPで得たクライアントIDやクライアントシークレットを設定します
bundle install
bundle exec rails s
```

ブラウザで http://localhost:3000 を開いてください。
