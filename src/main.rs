use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;
use std::sync::{Arc, Mutex};

use anyhow;
use oauth2::basic::{BasicClient, BasicTokenType};
use oauth2::reqwest::http_client;
use oauth2::{
    AuthUrl, AuthorizationCode, ClientId, ClientSecret, CsrfToken, DeviceAuthorizationUrl,
    EmptyExtraTokenFields, PkceCodeChallenge, RedirectUrl, ResponseType, RevocationUrl, Scope,
    StandardTokenResponse, TokenResponse, TokenUrl,
};
use once_cell::sync::OnceCell;
use url::Url;

pub mod openid_conf;

fn test_oauth() -> anyhow::Result<()> {
    // Create an OAuth2 client by specifying the client ID, client secret, authorization URL and
    // token URL.
    let client = BasicClient::new(
        ClientId::new("client_id".to_string()),
        Some(ClientSecret::new("client_secret".to_string())),
        AuthUrl::new("http://authorize".to_string())?,
        Some(TokenUrl::new("http://token".to_string())?),
    )
    // Set the URL the user will be redirected to after the authorization process.
    .set_redirect_uri(RedirectUrl::new("http://redirect".to_string())?);

    // Generate a PKCE challenge.
    let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();

    // Generate the full authorization URL.
    let (auth_url, csrf_token) = client
        .authorize_url(CsrfToken::new_random)
        // Set the desired scopes.
        .add_scope(Scope::new("read".to_string()))
        .add_scope(Scope::new("write".to_string()))
        // Set the PKCE code challenge.
        .set_pkce_challenge(pkce_challenge)
        .url();

    // This is the URL you should redirect the user to, in order to trigger the authorization
    // process.
    println!("Browse to: {}", auth_url);

    // Once the user has been redirected to the redirect URL, you'll have access to the
    // authorization code. For security reasons, your code should verify that the `state`
    // parameter returned by the server matches `csrf_state`.

    // Now you can trade it for an access token.
    let token_result = client
        .exchange_code(AuthorizationCode::new(
            "some authorization code".to_string(),
        ))
        // Set the PKCE code verifier.
        .set_pkce_verifier(pkce_verifier)
        .request(http_client)?;

    anyhow::Ok(())
}

fn main() -> anyhow::Result<()> {
    println!("Hello, world!");
    let http_client_ = reqwest::blocking::Client::new();
    let req = http_client_
        .get("https://auth.mangadex.dev/realms/mangadex/.well-known/openid-configuration");
    let conf: openid_conf::OpenIDConfig = serde_json::from_str(req.send()?.text()?.as_str())?;
    let issuer: openid_conf::Issuer =
        serde_json::from_str(http_client_.get(conf.issuer).send()?.text()?.as_str())?;
    let client = BasicClient::new(
        ClientId::new("thirdparty-oauth-client".to_string()),
        //Some(ClientSecret::new("client_secret".to_string())),
        Some(ClientSecret::new(issuer.public_key)),
        AuthUrl::new(conf.authorization_endpoint)?,
        Some(TokenUrl::new(conf.token_endpoint)?),
    )
    // Set the URL the user will be redirected to after the authorization process.
    .set_redirect_uri(RedirectUrl::new("http://localhost:8080".to_string())?)
    .set_revocation_uri(RevocationUrl::new(conf.revocation_endpoint)?)
    .set_device_authorization_url(DeviceAuthorizationUrl::new(
        conf.device_authorization_endpoint,
    )?);
    let mut scopes: Vec<Scope> = Vec::new();
    conf.scopes_supported.iter().for_each(|data| {
        let scopes = &mut scopes;
        scopes.push(Scope::new(format!("{}", data)));
    });
    let (authorize_url, csrf_state) = client
        .authorize_url(CsrfToken::new_random)
        .set_response_type(&ResponseType::new("code".to_string()))
        .add_scopes(scopes.into_iter())
        .url();
    println!(
        "Open this URL in your browser:\n{}\n",
        authorize_url.to_string()
    );
    let mut mangadex_token: OnceCell<StandardTokenResponse<EmptyExtraTokenFields, BasicTokenType>> =
        OnceCell::new();

    // A very naive implementation of the redirect server.
    let listener = TcpListener::bind("127.0.0.1:8080").unwrap();
    for stream in listener.incoming() {
        if let Ok(mut stream) = stream {
            let code;
            let state;
            {
                let mut reader = BufReader::new(&stream);

                let mut request_line = String::new();
                reader.read_line(&mut request_line).unwrap();

                let redirect_url = request_line.split_whitespace().nth(1).unwrap();
                let url = Url::parse(&("http://localhost".to_string() + redirect_url)).unwrap();

                let code_pair = url
                    .query_pairs()
                    .find(|pair| {
                        let &(ref key, _) = pair;
                        key == "code"
                    })
                    .unwrap();

                let (_, value) = code_pair;
                code = AuthorizationCode::new(value.into_owned());

                let state_pair = url
                    .query_pairs()
                    .find(|pair| {
                        let &(ref key, _) = pair;
                        key == "state"
                    })
                    .unwrap();

                let (_, value) = state_pair;
                state = CsrfToken::new(value.into_owned());
            }

            let message = "Go back to your terminal :)";
            let response = format!(
                "HTTP/1.1 200 OK\r\ncontent-length: {}\r\n\r\n{}",
                message.len(),
                message
            );
            stream.write_all(response.as_bytes()).unwrap();

            println!("Mangadex returned the following code:\n{}\n", code.secret());
            println!(
                "Mangadex returned the following state:\n{} (expected `{}`)\n",
                state.secret(),
                csrf_state.secret()
            );

            // Exchange the code with a token.
            let token_res = client.exchange_code(code).request(http_client);

            match token_res {
                Ok(token_res_) => {
                    match mangadex_token.take() {
                        None => (),
                        Some(_) => (),
                    };
                    mangadex_token.set(token_res_).unwrap();
                }
                Err(err) => {
                    println!("Error on getting the token : {}", err.to_string());
                }
            }
            // The server will terminate itself after collecting the first code.
            break;
        }
    }

    let mut input = String::new();
    loop {
        println!("0 exit");
        println!("1 refresh token");
        println!("2 get access and refresh token");
        println!("");
        std::io::stdin().read_line(&mut input).unwrap();
            match input.split_once("\n").unwrap().0 {
                "0" => break,
                "1" => {
                    let token_res_ = mangadex_token.get().unwrap();
                    match token_res_.refresh_token() {
                        Some(refresh_token) => {
                            match client
                                .exchange_refresh_token(refresh_token)
                                .request(http_client)
                            {
                                Ok(token) => {
                                    match mangadex_token.take() {
                                        None => (),
                                        Some(_) => (),
                                    };
                                    mangadex_token.set(token).unwrap();
                                    let token_res_ = mangadex_token.get().unwrap();
                                    println!(
                                        "Mangadex returned the following token:\n{:?}\n",
                                        token_res_
                                    );
                                    println!(
                                        "access-token : {}\n",
                                        token_res_.access_token().secret()
                                    );
                                    match token_res_.refresh_token() {
                                        None => {
                                            println!("No refresh token given");
                                        }
                                        Some(refresh_token) => {
                                            println!("refresh-token : {}\n", refresh_token.secret())
                                        }
                                    }
                                }
                                Err(err) => {
                                    println!("Error on getting the token : {}", err.to_string());
                                }
                            }
                        }
                        None => {
                            println!("the refresh token is null");
                        }
                    }
                },
                "2" => {
                    let token_res_ = mangadex_token.get().unwrap();
                    println!("access-token : {}\n", token_res_.access_token().secret());
                    match token_res_.refresh_token() {
                        None => {
                            println!("No refresh token given");
                        }
                        Some(refresh_token) => {
                            println!("refresh-token : {}\n", refresh_token.secret())
                        }
                    }
                }
                _ => {}
            }
        input = String::new();
    }

    anyhow::Ok(())
}
