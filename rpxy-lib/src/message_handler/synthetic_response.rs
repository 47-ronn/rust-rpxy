use super::http_result::{HttpError, HttpResult};
use crate::{
  error::*,
  hyper_ext::body::{ResponseBody, empty},
  name_exp::ServerName,
};
use http::{Request, Response, StatusCode, Uri};

/// build http response with status code of 4xx and 5xx
pub(crate) fn synthetic_error_response(status_code: StatusCode) -> RpxyResult<Response<ResponseBody>> {
  let res = Response::builder()
    .status(status_code)
    .body(ResponseBody::Boxed(empty()))
    .unwrap();
  Ok(res)
}

/// Generate synthetic response message of a redirection to https host with 301
pub(super) fn secure_redirection_response<B>(
  server_name: &ServerName,
  tls_port: Option<u16>,
  req: &Request<B>,
) -> HttpResult<Response<ResponseBody>> {
  let server_name: String = server_name.try_into().unwrap_or_default();
  let pq = match req.uri().path_and_query() {
    Some(x) => x.as_str(),
    _ => "",
  };
  let new_uri = Uri::builder().scheme("https").path_and_query(pq);
  let dest_uri = match tls_port {
    Some(443) | None => new_uri.authority(server_name),
    Some(p) => new_uri.authority(format!("{server_name}:{p}")),
  }
  .build()
  .map_err(|e| HttpError::FailedToRedirect(e.to_string()))?;
  let response = Response::builder()
    .status(StatusCode::MOVED_PERMANENTLY)
    .header("Location", dest_uri.to_string())
    .body(ResponseBody::Boxed(empty()))
    .map_err(|e| HttpError::FailedToRedirect(e.to_string()))?;
  Ok(response)
}

/// Generate a synthetic redirect response to an arbitrary target with a configurable status code
pub(super) fn custom_redirection_response<B>(
  redirect: &crate::globals::RedirectConfig,
  req: &Request<B>,
) -> HttpResult<Response<ResponseBody>> {
  let status = StatusCode::from_u16(redirect.status).map_err(|e| HttpError::FailedToRedirect(e.to_string()))?;

  let location = if redirect.preserve_path {
    let base = redirect
      .target
      .parse::<Uri>()
      .map_err(|e| HttpError::FailedToRedirect(e.to_string()))?;
    let scheme = base
      .scheme_str()
      .ok_or_else(|| HttpError::FailedToRedirect("redirect target has no scheme".to_string()))?;
    let authority = base
      .authority()
      .ok_or_else(|| HttpError::FailedToRedirect("redirect target has no authority".to_string()))?
      .clone();
    let pq = req.uri().path_and_query().map(|x| x.as_str()).unwrap_or("/");
    Uri::builder()
      .scheme(scheme)
      .authority(authority)
      .path_and_query(pq)
      .build()
      .map_err(|e| HttpError::FailedToRedirect(e.to_string()))?
      .to_string()
  } else {
    redirect.target.clone()
  };

  let response = Response::builder()
    .status(status)
    .header("Location", location)
    .body(ResponseBody::Boxed(empty()))
    .map_err(|e| HttpError::FailedToRedirect(e.to_string()))?;
  Ok(response)
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::globals::RedirectConfig;
  use http::Request;

  fn req(uri: &str) -> Request<()> {
    Request::builder().uri(uri).body(()).unwrap()
  }

  #[test]
  fn preserves_path_and_query_with_301() {
    let r = RedirectConfig { target: "https://new.example.com".into(), status: 301, preserve_path: true };
    let resp = custom_redirection_response(&r, &req("http://old.example.com/foo/bar?x=1&y=2")).unwrap();
    assert_eq!(resp.status(), StatusCode::MOVED_PERMANENTLY);
    assert_eq!(resp.headers()["location"], "https://new.example.com/foo/bar?x=1&y=2");
  }

  #[test]
  fn ignores_path_when_preserve_false() {
    let r = RedirectConfig { target: "https://new.example.com/landing".into(), status: 302, preserve_path: false };
    let resp = custom_redirection_response(&r, &req("http://old.example.com/foo?x=1")).unwrap();
    assert_eq!(resp.status(), StatusCode::FOUND);
    assert_eq!(resp.headers()["location"], "https://new.example.com/landing");
  }

  #[test]
  fn honors_custom_status_308() {
    let r = RedirectConfig { target: "https://new.example.com".into(), status: 308, preserve_path: true };
    let resp = custom_redirection_response(&r, &req("http://old.example.com/")).unwrap();
    assert_eq!(resp.status(), StatusCode::PERMANENT_REDIRECT);
    assert_eq!(resp.headers()["location"], "https://new.example.com/");
  }
}
