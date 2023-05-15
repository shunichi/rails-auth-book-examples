class SessionsController < ApplicationController
  def new
  end

  def create
    user = User.find_for_authentication(params[:login_id])
    if user&.valid_password?(params[:password])
      # ログイン成功の処理
      session[:user_id] = user.id
      redirect_to root_url, notice: 'ログインしました'
    else
      # ログイン失敗したらもう一度ログインフォームを表示
      flash.now[:alert] = 'ユーザーIDまたはパスワードが間違っています'
      render :new, status: :unprocessable_entity
    end
  end

  def destroy
    session.delete(:user_id)
    redirect_to root_url, notice: 'ログアウトしました'
  end
end
