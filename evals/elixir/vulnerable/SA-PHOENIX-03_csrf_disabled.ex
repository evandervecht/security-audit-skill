defmodule MyAppWeb.Router do
  use MyAppWeb, :router

  pipeline :browser do
    plug :accepts, ["html"]
    plug :fetch_session
    plug :fetch_live_flash
    plug :put_root_layout, html: {MyAppWeb.Layouts, :root}
    plug :put_secure_browser_headers
    # VULNERABLE: CSRF protection commented out — cookie-authenticated
    # POST/PUT/DELETE requests can be forged from other origins.
    # plug :protect_from_forgery
  end
end
