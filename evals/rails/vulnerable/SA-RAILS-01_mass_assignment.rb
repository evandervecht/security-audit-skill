# SA-RAILS-01: Mass assignment via permit!
class UsersController < ApplicationController
  def create
    @user = User.new(params[:user].permit!)
    @user.save
    redirect_to @user
  end
end
