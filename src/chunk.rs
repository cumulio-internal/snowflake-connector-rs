use std::io::Read;

use flate2::bufread::GzDecoder;
use reqwest::header::HeaderMap;

use crate::{Error, Result};

const HEADER_SSE_C_ALGORITHM: &str = "x-amz-server-side-encryption-customer-algorithm";
const HEADER_SSE_C_KEY: &str = "x-amz-server-side-encryption-customer-key";
const AES256: &str = "AES256";

pub(crate) async fn download_chunk(
    client: &reqwest::Client,
    chunk_url: &str,
    chunk_headers: &HeaderMap,
    qrmk: &str,
) -> Result<Vec<Vec<Option<String>>>> {
    let mut headers = chunk_headers.clone();
    if headers.is_empty() {
        headers.append(HEADER_SSE_C_ALGORITHM, AES256.parse()?);
        headers.append(HEADER_SSE_C_KEY, qrmk.parse()?);
    }

    let response = client.get(chunk_url).headers(headers).send().await?;
    if !response.status().is_success() {
        let body = response.text().await?;
        return Err(Error::ChunkDownload(body));
    }

    let body = response.bytes().await?;
    if body.len() < 2 {
        return Err(Error::ChunkDownload("invalid chunk format".into()));
    }

    let bytes = if body[0] == 0x1f && body[1] == 0x8b {
        let mut d = GzDecoder::new(&body[..]);
        let mut buf = vec![];
        d.read_to_end(&mut buf)?;
        buf
    } else {
        body.to_vec()
    };

    let mut buf = vec![b'['];
    buf.extend(bytes);
    buf.push(b']');
    let rows: Vec<Vec<Option<String>>> = serde_json::from_slice(&buf)?;
    Ok(rows)
}
