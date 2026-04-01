# SA-RAILS-01: Safe strong parameters — only safe fields permitted
class UsersController < ApplicationController
  def create
    @user = User.new(user_params)
    @user.role = "user"
    @user.save
    redirect_to @user
  end

  private

  def user_params
    params.require(:user).permit(:name, :email, :bio)
  end
end
