class ApplicationController < ActionController::Base
  # Prevent CSRF attacks by raising an exception.
  # For APIs, you may want to use :null_session instead.
  protect_from_forgery with: :exception
  before_action :authenticate_user

  private

  def authenticate_user
    unless logged_in?
      github_oauth_url = "https://github.com/login/oauth/authorize"
      redirect_uri = CGI.escape("http://localhost:3000/auth")
      client_id = ENV['GITHUB_CLIENT_ID']
      github_url = "https://github.com/login/oauth/authorize?client_id=#{client_id}&scope=repo"
      redirect_to github_url
    end
  end

  def logged_in?
    !!session[:token]
  end
end
