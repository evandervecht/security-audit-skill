defmodule MyApp.Posts do
  import Ecto.Query
  alias MyApp.{Post, Repo}

  # SAFE: use a ? placeholder in the fragment and pass the pinned value as
  # a parameter — Ecto sends it as a bound parameter, not inline SQL.
  def search(term) do
    from(p in Post, where: fragment("title LIKE ?", ^"%#{term}%"))
    |> Repo.all()
  end

  # SAFE: idiomatic keyword query with a pinned variable.
  def by_status(status) do
    Repo.all(from p in Post, where: p.status == ^status)
  end
end
