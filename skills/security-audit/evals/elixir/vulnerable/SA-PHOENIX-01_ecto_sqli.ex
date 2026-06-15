defmodule MyApp.Posts do
  import Ecto.Query
  alias MyApp.{Post, Repo}

  # VULNERABLE: interpolating user input into a fragment string builds raw
  # SQL — term="%' OR '1'='1" leaks every row / enables injection.
  def search(term) do
    from(p in Post, where: fragment("title LIKE '%#{term}%'"))
    |> Repo.all()
  end

  # VULNERABLE: interpolated where: string fragment.
  def by_status(status) do
    Repo.all(from p in Post, where: "status = '#{status}'")
  end
end
