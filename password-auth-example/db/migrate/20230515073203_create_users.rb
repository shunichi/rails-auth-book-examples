class CreateUsers < ActiveRecord::Migration[7.0]
  def change
    create_table :users do |t|
      t.string :login_id, null: false, index: { unique: true }
      t.string :password_hash, null: false

      t.timestamps

    end
  end
end
