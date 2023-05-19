# 紙の書籍(ver 1.0)の正誤表

## 2ページ, 13ページ
* (誤) `user = User.find_for_authentication(prams[:login_id])`
* (正) `user = User.find_for_authentication(params[:login_id])`

## 17ページ
* (誤)  環境変数 secret_key_base
* (正)  環境変数 SECRET_KEY_BASE

