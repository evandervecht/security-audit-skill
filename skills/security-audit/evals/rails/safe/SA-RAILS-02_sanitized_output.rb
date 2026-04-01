# SA-RAILS-02: Safe output using content_tag and sanitize
module ApplicationHelper
  def render_username(user)
    content_tag(:strong, user.name)
  end

  def render_comment(comment)
    sanitize(comment.body, tags: %w[b i em strong p])
  end
end
