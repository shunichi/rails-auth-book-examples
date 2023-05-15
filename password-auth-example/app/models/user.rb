class User < ApplicationRecord
  validates :login_id, presence: true, uniqueness: true
  validates :password_hash, presence: true

  # 平文のパスワードを代入すると bcrypt で計算されたパスワードのハッシュ値がDBに保存される
  def password=(plain_password)
    return if plain_password.blank?

    self.password_hash = BCrypt::Password.create(plain_password)
  end

  # 入力された平文パスワードがDBに保存されたパスワードのハッシュ値と同じパスワードか検証する
  def valid_password?(input_password)
    bcrypt_password = BCrypt::Password.new(password_hash)
    bcrypt_password.is_password?(input_password)
  end

  def self.find_for_authentication(login_id)
    find_by(login_id: login_id)
  end
end
