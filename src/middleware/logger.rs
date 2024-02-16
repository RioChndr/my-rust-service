use std::time::Instant;

use axum::{extract::Request, http::StatusCode, middleware::Next, response::IntoResponse};

pub async fn logger_fn(
    req: Request,
    next: Next,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let time_before = Instant::now();
    let path_req = req.uri().clone();
    let res = next.run(req).await;
    let elapsed_time = time_before.elapsed();
    let path_req = path_req.path();
    let res_code = res.status().as_u16();
    tracing::debug!(
        "Req {} ({}ms) [{}]",
        path_req,
        elapsed_time.as_millis(),
        res_code,
    );

    Ok(res)
}
