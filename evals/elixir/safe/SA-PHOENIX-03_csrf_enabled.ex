defmodule MyAppWeb.Router do
  use MyAppWeb, :router

  pipeline :browser do
    plug :accepts, ["html"]
    plug :fetch_session
    plug :fetch_live_flash
    plug :put_root_layout, html: {MyAppWeb.Layouts, :root}
    # SAFE: protect_from_forgery verifies the CSRF token on state-changing
    # requests before any controller action runs.
    plug :protect_from_forgery
    plug :put_secure_browser_headers
  end
end
