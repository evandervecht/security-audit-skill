# SA-RAILS-02: html_safe on user input bypasses escaping
module ApplicationHelper
  def render_username(user)
    "<strong>#{user.name}</strong>".html_safe
  end
end
