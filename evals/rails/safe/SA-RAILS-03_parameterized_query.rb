# SA-RAILS-03: Safe parameterized query using ActiveRecord
class User < ApplicationRecord
  def self.search(query)
    where("name LIKE ?", "%#{sanitize_sql_like(query)}%")
  end
end
