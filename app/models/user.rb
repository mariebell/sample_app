class User < ApplicationRecord
    attr_accessor :remember_token

    before_save { email.downcase! }
    validates :name,
        presence: true,
        length: { maximum: 50 }
    
    VALID_EMAIL_REGEX = /\A[\w+\-.]+@[a-z\d\-]+(\.[a-z\d\-]+)*\.[a-z]+\z/i
    validates :email,
        presence: true,
        length: { maximum: 255 },
        format: { with: VALID_EMAIL_REGEX },
        uniqueness: { case_sensitive: false }

    has_secure_password
    validates :password,
        presence: true,
        length: { minimum: 6 },
        allow_nil: true;

    # 引数(string)のハッシュ値をreturnする
    def self.digest(string)
        cost = ActiveModel::SecurePassword.min_cost ?
            BCrypt::Engine::MIN_COST : BCrypt::Engine.cost
        BCrypt::Password.create(string, cost: cost)
    end

    # ランダムなトークンをreturnする
    def self.new_token
        SecureRandom.urlsafe_base64
    end

    #ユーザのトークン(remember_token)をハッシュ化してデータベースに保存
    def remember
        self.remember_token = User.new_token
        update_attribute(:remember_digest, User.digest(remember_token))
    end

    # 渡されたトークンがダイジェストと一致したらtrueを返す
    def authenticated?(token)
        return false if remember_digest.nil?
        BCrypt::Password.new(remember_digest).is_password?(token)
    end

    # ユーザーのログイン情報を破棄する
    def forget
        update_attribute(:remember_digest, nil)
    end
end
