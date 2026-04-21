defmodule PlausibleWeb.OIDCController do
  @moduledoc """
  OpenID Connect authentication controller.
  Handles OIDC login flow: redirect to provider -> callback with code -> exchange -> find/create user.
  """
  use PlausibleWeb, :controller
  use Plausible.Repo

  alias Plausible.Auth
  alias PlausibleWeb.UserAuth

  def login(conn, _params) do
    case oidc_config() do
      nil ->
        conn
        |> put_flash(:error, "OIDC not configured")
        |> redirect(to: "/login")

      config ->
        case discover(config.issuer) do
          {:ok, discovery} ->
            params =
              URI.encode_query(%{
                client_id: config.client_id,
                redirect_uri: oidc_callback_url(),
                response_type: "code",
                scope: "openid email profile"
              })

            redirect(conn, external: "#{discovery["authorization_endpoint"]}?#{params}")

          {:error, _} ->
            conn
            |> put_flash(:error, "OIDC discovery failed")
            |> redirect(to: "/login")
        end
    end
  end

  def callback(conn, %{"code" => code}) do
    config = oidc_config()

    with {:ok, discovery} <- discover(config.issuer),
         {:ok, tokens} <- exchange_code(discovery["token_endpoint"], config, code),
         {:ok, userinfo} <- fetch_userinfo(discovery["userinfo_endpoint"], tokens["access_token"]) do
      email = userinfo["email"]
      name = userinfo["name"] || userinfo["given_name"] || email

      user =
        case Repo.get_by(Auth.User, email: String.downcase(email)) do
          nil ->
            password = Ecto.UUID.generate() <> Ecto.UUID.generate()

            {:ok, new_user} =
              Auth.User.new(%{name: name, email: email, password: password, password_confirmation: password})
              |> Repo.insert()

            new_user

          existing ->
            existing
        end

      conn
      |> UserAuth.log_in_user(user)
      |> redirect(to: "/")
    else
      _ ->
        conn
        |> put_flash(:error, "OIDC authentication failed")
        |> redirect(to: "/login")
    end
  end

  def callback(conn, _params) do
    conn
    |> put_flash(:error, "OIDC authentication error")
    |> redirect(to: "/login")
  end

  defp oidc_config do
    issuer = Application.get_env(:plausible, :oidc_issuer)
    client_id = Application.get_env(:plausible, :oidc_client_id)
    client_secret = Application.get_env(:plausible, :oidc_client_secret)

    if issuer && client_id && client_secret do
      %{issuer: issuer, client_id: client_id, client_secret: client_secret}
    else
      nil
    end
  end

  defp oidc_callback_url do
    PlausibleWeb.Endpoint.url() <> "/auth/oidc/callback"
  end

  defp discover(issuer) do
    url = String.trim_trailing(issuer, "/") <> "/.well-known/openid-configuration"

    case Req.get(url) do
      {:ok, %{status: 200, body: body}} -> {:ok, body}
      _ -> {:error, :discovery_failed}
    end
  end

  defp exchange_code(token_endpoint, config, code) do
    body =
      URI.encode_query(%{
        grant_type: "authorization_code",
        code: code,
        client_id: config.client_id,
        client_secret: config.client_secret,
        redirect_uri: oidc_callback_url()
      })

    case Req.post(token_endpoint, body: body, headers: [{"content-type", "application/x-www-form-urlencoded"}]) do
      {:ok, %{status: 200, body: body}} -> {:ok, body}
      _ -> {:error, :token_exchange_failed}
    end
  end

  defp fetch_userinfo(userinfo_endpoint, access_token) do
    case Req.get(userinfo_endpoint, headers: [{"authorization", "Bearer #{access_token}"}]) do
      {:ok, %{status: 200, body: body}} -> {:ok, body}
      _ -> {:error, :userinfo_failed}
    end
  end
end
