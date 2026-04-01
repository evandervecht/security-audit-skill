# SA-RAILS-03: SQL injection via string interpolation in find_by_sql
class User < ApplicationRecord
  def self.search(query)
    find_by_sql("SELECT * FROM users WHERE name LIKE '%#{query}%'")
  end
end
