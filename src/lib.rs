#[macro_use]
extern crate pamsm;

use config::Config;
use ldap3::LdapError;
use pamsm::{Pam, PamError, PamFlags, PamLibExt, PamMsgStyle, PamServiceModule};
use serde::Deserialize;
use std::collections::HashMap;
use yubico::yubicoerror::YubicoError;

struct PamMultifac;

static HTTP_TIMEOUT: u64 = 30;
static LDAP_TIMEOUT: u64 = 30;

#[derive(Deserialize, Debug)]
struct DuoAuthResponse {
    response: AuthResponse,
}

#[derive(Deserialize, Debug)]
struct AuthResponse {
    result: String,
}

#[derive(Deserialize, Debug)]
struct PamConfig {
    duo: DuoConfig,
    ldap: LdapConfig,
    yubico: YubicoConfig,
}

#[derive(Deserialize, Debug)]
struct DuoConfig {
    integration_key: String,
    secret_key: String,
    api_hostname: String,
}

#[derive(Deserialize, Debug)]
struct LdapConfig {
    url: String,
    bind_dn: String,
    bind_pw: String,
    search_base: String,
    search_filter: String,
    search_attr: String,
}

#[derive(Deserialize, Debug)]
struct YubicoConfig {
    client_id: String,
    api_key: String,
}

impl PamServiceModule for PamMultifac {
    fn authenticate(pamh: Pam, _: PamFlags, args: Vec<String>) -> PamError {
        let arg_map: HashMap<&str, &str> = args
            .iter()
            .map(|s| {
                let mut parts = s.splitn(2, "=");
                (parts.next().unwrap(), parts.next().unwrap_or(""))
            })
            .collect();

        let cfg = match Config::builder()
            .add_source(config::File::with_name(
                arg_map.get("config").unwrap_or(&"/etc/pam_multifac.toml"),
            ))
            .build()
        {
            Ok(s) => match s.try_deserialize::<PamConfig>() {
                Ok(m) => m,
                Err(e) => {
                    println!("Error: {}", e);
                    return PamError::ABORT;
                }
            },
            Err(e) => {
                println!("Error: {}", e);
                return PamError::ABORT;
            }
        };

        let user = match pamh.get_user(None) {
            Ok(Some(u)) => match u.to_str() {
                Ok(s) => s,
                Err(_) => return PamError::AUTH_ERR,
            },
            Ok(None) => return PamError::USER_UNKNOWN,
            Err(e) => return e,
        };

        let input = match pamh.conv(
            Some("Touch YubiKey or type \"push\" for Duo push: "),
            PamMsgStyle::PROMPT_ECHO_ON,
        ) {
            Ok(Some(u)) => match u.to_str() {
                Ok(s) => s,
                Err(_) => return PamError::AUTH_ERR,
            },
            Ok(None) => return PamError::AUTH_ERR,
            Err(e) => return e,
        };

        if input == "push" {
            match validate_duo(
                user,
                &cfg.duo.integration_key,
                &cfg.duo.secret_key,
                &cfg.duo.api_hostname,
            ) {
                Ok(resp) => {
                    let auth_resp = match resp.json::<DuoAuthResponse>() {
                        Ok(t) => t,
                        Err(e) => {
                            println!("Error: {}", e);
                            return PamError::AUTH_ERR;
                        }
                    };
                    if auth_resp.response.result == "allow" {
                        return PamError::SUCCESS;
                    }
                    return PamError::AUTH_ERR;
                }
                Err(e) => {
                    println!("Error: {}", e);
                    return PamError::AUTH_ERR;
                }
            }
        } else {
            let registration = match validate_otp(input, cfg.yubico) {
                Ok(_) => validate_registration(user, input, cfg.ldap),
                Err(e) => {
                    println!("Error: {}", e);
                    return PamError::AUTH_ERR;
                }
            };
            let registered = match registration {
                Ok(b) => b,
                Err(e) => {
                    println!("Error: {}", e);
                    return PamError::AUTH_ERR;
                }
            };
            if !registered {
                println!("Error: YubiKey is not registered in LDAP.");
                return PamError::AUTH_ERR;
            }
            return PamError::SUCCESS;
        }
    }

    fn setcred(_pamh: Pam, _: PamFlags, _args: Vec<String>) -> PamError {
        PamError::SUCCESS
    }

    fn acct_mgmt(_pamh: Pam, _: PamFlags, _args: Vec<String>) -> PamError {
        PamError::SUCCESS
    }
}

fn validate_registration(username: &str, token: &str, cfg: LdapConfig) -> Result<bool, LdapError> {
    use handlebars::Handlebars;
    use ldap3::{LdapConn, Scope, SearchEntry};
    use serde_json::json;

    let mut ldap = LdapConn::new(&cfg.url)?;
    let _res = ldap
        .with_timeout(std::time::Duration::from_secs(LDAP_TIMEOUT))
        .simple_bind(&cfg.bind_dn, &cfg.bind_pw)?
        .success()?;

    let template = match Handlebars::new()
        .render_template(&cfg.search_filter, &json!({ "username": username }))
    {
        Ok(t) => t,
        Err(e) => {
            println!("Error: {}", e);
            return Err(LdapError::FilterParsing);
        }
    };

    let (rs, _res) = ldap
        .search(
            &cfg.search_base,
            Scope::Subtree,
            &template,
            vec![&cfg.search_attr],
        )?
        .success()?;

    let mut registered = false;

    for entry in rs {
        let entry = SearchEntry::construct(entry);
        if !entry.attrs.contains_key(&cfg.search_attr) {
            continue;
        }

        let key_list = entry.attrs.get(&cfg.search_attr);

        match key_list {
            Some(l) => {
                let mut token_str = String::new();
                token_str.push_str(token);

                for val in l.iter() {
                    if val[..12] == token_str[..12] {
                        registered = true;
                        break;
                    }
                }
            }
            None => (),
        }
    }

    ldap.unbind()?;
    Ok(registered)
}

fn validate_otp(token: &str, cfg: YubicoConfig) -> Result<String, YubicoError> {
    let config = yubico::config::Config::default()
        .set_client_id(cfg.client_id)
        .set_key(cfg.api_key);

    yubico::verify(token, config)
}

fn validate_duo(
    username: &str,
    ikey: &str,
    skey: &str,
    apihost: &str,
) -> Result<reqwest::blocking::Response, reqwest::Error> {
    use chrono::offset::Utc;
    use reqwest::header;
    use std::time::Duration;

    let date = Utc::now().to_rfc2822();
    let method = "POST";
    let path = "/auth/v2/auth";
    let url = format!("https://{}{}", apihost, path);

    let params: HashMap<&str, &str> = [
        ("username", username),
        ("factor", "push"),
        ("device", "auto"),
    ]
    .iter()
    .cloned()
    .collect();

    let encoded_params = encode_params(&params);
    let fields = [&date, method, apihost, path, &encoded_params];
    let joined = &fields.join("\n");
    let password = hmac_sign(skey, joined);

    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(HTTP_TIMEOUT))
        .build()?;
    return client
        .post(url)
        .basic_auth(ikey, Some(password))
        .header(header::DATE, date)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .query(&params)
        .send();
}

fn hmac_sign(key: &str, data: &str) -> String {
    use data_encoding::HEXLOWER;
    use ring::hmac;

    let key = hmac::Key::new(hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, key.as_bytes());
    let signature = hmac::sign(&key, data.as_bytes());

    HEXLOWER.encode(signature.as_ref())
}

fn encode_params(params: &HashMap<&str, &str>) -> String {
    let mut sorted_keys: Vec<_> = params.keys().collect();
    sorted_keys.sort();
    let mut encoder = url::form_urlencoded::Serializer::new(String::new());
    for k in sorted_keys {
        encoder.append_pair(k, params[k]); // safe
    }

    encoder.finish()
}

pam_module!(PamMultifac);
