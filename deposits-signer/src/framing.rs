//! Length-prefixed JSON framing over an async stream.
//!
//! v1 wire: `[len: u32 big-endian][json bytes]`. Cap at 1 MiB to bound the
//! signer's per-connection memory; signing requests are ~hundreds of bytes,
//! handshake messages even smaller.
//!
//! AEAD sealing of post-handshake frames is a future-phase concern (the
//! local-Unix-socket case doesn't strictly need it; phase 4 keeps it
//! plaintext over `SOCK_STREAM` whose access is gated by filesystem perms
//! plus the mutual-pinned-keys handshake).

use serde::{de::DeserializeOwned, Serialize};
use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const MAX_FRAME_LEN: u32 = 1 << 20;

#[derive(Debug, Error)]
pub enum FrameError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("frame too large: {0} > {MAX_FRAME_LEN}")]
    TooLarge(u32),
    #[error("peer closed before frame fully read")]
    Eof,
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
}

pub async fn read_frame<S, T>(stream: &mut S) -> Result<T, FrameError>
where
    S: tokio::io::AsyncRead + Unpin,
    T: DeserializeOwned,
{
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).await.map_err(|e| {
        if e.kind() == std::io::ErrorKind::UnexpectedEof {
            FrameError::Eof
        } else {
            FrameError::Io(e)
        }
    })?;
    let len = u32::from_be_bytes(len_buf);
    if len > MAX_FRAME_LEN {
        return Err(FrameError::TooLarge(len));
    }
    let mut body = vec![0u8; len as usize];
    stream.read_exact(&mut body).await?;
    let value = serde_json::from_slice(&body)?;
    Ok(value)
}

pub async fn write_frame<S, T>(stream: &mut S, value: &T) -> Result<(), FrameError>
where
    S: tokio::io::AsyncWrite + Unpin,
    T: Serialize,
{
    let body = serde_json::to_vec(value)?;
    let len = body.len();
    if len > MAX_FRAME_LEN as usize {
        return Err(FrameError::TooLarge(len as u32));
    }
    let mut buf = Vec::with_capacity(4 + len);
    buf.extend_from_slice(&(len as u32).to_be_bytes());
    buf.extend_from_slice(&body);
    stream.write_all(&buf).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::{Deserialize, Serialize};
    use tokio::io::duplex;

    #[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
    struct Sample {
        n: u64,
        s: String,
    }

    #[tokio::test]
    async fn round_trip_one_frame() {
        let (mut a, mut b) = duplex(1024);
        let sent = Sample {
            n: 42,
            s: "hello".to_string(),
        };
        write_frame(&mut a, &sent).await.unwrap();
        let got: Sample = read_frame(&mut b).await.unwrap();
        assert_eq!(sent, got);
    }

    #[tokio::test]
    async fn round_trip_three_frames() {
        let (mut a, mut b) = duplex(4096);
        let writer = tokio::spawn(async move {
            for n in 0..3u64 {
                write_frame(
                    &mut a,
                    &Sample {
                        n,
                        s: format!("frame{}", n),
                    },
                )
                .await
                .unwrap();
            }
        });
        for n in 0..3u64 {
            let got: Sample = read_frame(&mut b).await.unwrap();
            assert_eq!(got.n, n);
        }
        writer.await.unwrap();
    }

    #[tokio::test]
    async fn rejects_over_max() {
        let (mut a, mut b) = duplex(8);
        // Write a length header that claims a huge frame; reader should refuse.
        let huge = (MAX_FRAME_LEN + 1).to_be_bytes();
        a.write_all(&huge).await.unwrap();
        let res: Result<Sample, _> = read_frame(&mut b).await;
        assert!(matches!(res, Err(FrameError::TooLarge(_))));
    }

    #[tokio::test]
    async fn eof_during_header_propagates() {
        let (a, mut b) = duplex(4);
        drop(a);
        let res: Result<Sample, _> = read_frame(&mut b).await;
        assert!(matches!(res, Err(FrameError::Eof)));
    }
}
