/*
Copyright 2019 Adam Reichold

This file is part of b2_backup.

b2_backup is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

b2_backup is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with b2_backup.  If not, see <https://www.gnu.org/licenses/>.
*/
use std::collections::HashMap;
use std::io::Read;
use std::sync::Mutex;
use std::thread::{current, sleep, ThreadId};
use std::time::Duration;

use aws_lc_rs::digest::{digest, SHA1_FOR_LEGACY_USE_ONLY};
use base64::{engine::general_purpose::STANDARD, Engine};
use serde::{Deserialize, Serialize};
use zeptohttpc::{
    http::{
        header::{AUTHORIZATION, CONTENT_TYPE},
        Request,
    },
    RequestBuilderExt, RequestExt, ResponseExt,
};

use super::{
    pack::{pack, unpack, Key},
    Bytes, Config, Fallible,
};

pub struct Client<'a> {
    config: &'a Config,
    key: Key,
    token: String,
    api_url: String,
    download_url: String,
    uploader: Mutex<HashMap<ThreadId, Uploader>>,
}

impl<'a> Client<'a> {
    pub fn new(config: &'a Config) -> Fallible<Self> {
        let resp = Request::get("https://api.backblazeb2.com/b2api/v2/b2_authorize_account")
            .header(
                AUTHORIZATION,
                format!(
                    "Basic {}",
                    STANDARD.encode(format!("{}:{}", config.app_key_id, config.app_key))
                ),
            )
            .empty()?
            .send()?;

        if !resp.status().is_success() {
            return Err(format!(
                "Failed to authorize: {} {}",
                resp.status(),
                resp.into_string()?
            )
            .into());
        }

        #[derive(Debug, Deserialize)]
        struct Response {
            #[serde(rename = "authorizationToken")]
            token: String,
            #[serde(rename = "apiUrl")]
            api_url: String,
            #[serde(rename = "downloadUrl")]
            download_url: String,
        }

        let resp: Response = resp.json()?;

        Ok(Self {
            config,
            key: config.key()?,
            token: resp.token,
            api_url: resp.api_url,
            download_url: resp.download_url,
            uploader: Mutex::new(HashMap::new()),
        })
    }

    pub fn download(&self, name: &str) -> Fallible<impl Read> {
        println!("Downloading {name}...");

        let resp = Request::get(format!(
            "{}/file/{}/{}",
            self.download_url, self.config.bucket_name, name
        ))
        .header(AUTHORIZATION, &self.token)
        .empty()?
        .send()?;

        if !resp.status().is_success() {
            return Err(format!(
                "Failed to download file: {} {}",
                resp.status(),
                resp.into_string()?
            )
            .into());
        }

        unpack(&self.key, name, resp.into_vec()?)
    }

    pub fn remove(&self, name: &str, id: &str) -> Fallible {
        println!("Removing {name}...");

        #[derive(Serialize)]
        struct Body<'a> {
            #[serde(rename = "fileName")]
            name: &'a str,
            #[serde(rename = "fileId")]
            id: &'a str,
        }

        let resp = Request::post(format!("{}/b2api/v2/b2_delete_file_version", self.api_url))
            .header(AUTHORIZATION, &self.token)
            .json_buffered(&Body { name, id })?
            .send()?;

        if !resp.status().is_success() {
            return Err(format!(
                "Failed to remove file: {} {}",
                resp.status(),
                resp.into_string()?
            )
            .into());
        }

        Ok(())
    }

    pub fn list(&self, prefix: &str) -> Fallible<Vec<(String, String, u64)>> {
        let mut files = Vec::new();
        let mut start = None;

        loop {
            #[derive(Serialize)]
            struct Body<'a> {
                #[serde(rename = "bucketId")]
                bucket_id: &'a str,
                prefix: &'a str,
                #[serde(rename = "startFileName")]
                start: Option<String>,
                #[serde(rename = "maxFileCount")]
                count: i32,
            }

            let resp = Request::post(format!("{}/b2api/v2/b2_list_file_names", self.api_url))
                .header(AUTHORIZATION, &self.token)
                .json_buffered(&Body {
                    bucket_id: &self.config.bucket_id,
                    prefix,
                    start,
                    count: 1000,
                })?
                .send()?;

            if !resp.status().is_success() {
                return Err(format!(
                    "Failed to list files: {} {}",
                    resp.status(),
                    resp.into_string()?
                )
                .into());
            }

            #[derive(Deserialize)]
            struct File {
                #[serde(rename = "fileName")]
                name: String,
                #[serde(rename = "fileId")]
                id: String,
                #[serde(rename = "contentLength")]
                length: u64,
            }

            #[derive(Deserialize)]
            struct Response {
                files: Vec<File>,
                #[serde(rename = "nextFileName")]
                next: Option<String>,
            }

            let resp: Response = resp.json()?;

            for file in resp.files {
                files.push((file.name, file.id, file.length));
            }

            match resp.next {
                Some(next) => start = Some(next),
                None => break,
            }
        }

        Ok(files)
    }

    pub fn upload(&self, name: &str, reader: impl Read) -> Fallible<(String, u64)> {
        let buf = pack(&self.key, self.config.compression_level, name, reader)?;

        let thread_id = current().id();

        let mut cnt = 0;
        let mut dur = Duration::from_secs(1);

        loop {
            let uploader = self.uploader.lock().unwrap().remove(&thread_id);

            let uploader = match uploader {
                Some(uploader) => uploader,
                None => self.uploader()?,
            };

            match uploader.upload(name, &buf) {
                Ok(file_id) => {
                    self.uploader.lock().unwrap().insert(thread_id, uploader);

                    return Ok((file_id, buf.len().try_into().unwrap()));
                }
                Err(err) => {
                    cnt += 1;

                    if cnt == 5 {
                        return Err(err);
                    }

                    eprintln!("Retrying failed upload of {name}: {err}");
                }
            }

            sleep(dur);
            dur *= 2;
        }
    }

    fn uploader(&self) -> Fallible<Uploader> {
        #[derive(Serialize)]
        struct Body<'a> {
            #[serde(rename = "bucketId")]
            bucket_id: &'a str,
        }

        let resp = Request::post(format!("{}/b2api/v2/b2_get_upload_url", self.api_url))
            .header(AUTHORIZATION, &self.token)
            .json_buffered(&Body {
                bucket_id: &self.config.bucket_id,
            })?
            .send()?;

        if !resp.status().is_success() {
            return Err(format!(
                "Failed to prepare uploader: {} {}",
                resp.status(),
                resp.into_string()?
            )
            .into());
        }

        #[derive(Deserialize)]
        struct Response {
            #[serde(rename = "uploadUrl")]
            url: String,
            #[serde(rename = "authorizationToken")]
            token: String,
        }

        let resp: Response = resp.json()?;

        Ok(Uploader {
            url: resp.url,
            token: resp.token,
        })
    }
}

struct Uploader {
    url: String,
    token: String,
}

impl Uploader {
    fn upload(&self, name: &str, buf: &[u8]) -> Fallible<String> {
        println!("Uploading {} to {}...", Bytes(buf.len() as _), name);

        let resp = Request::post(&self.url)
            .header(AUTHORIZATION, &self.token)
            .header(CONTENT_TYPE, "application/octet-stream")
            .header("X-Bz-File-Name", name)
            .header(
                "X-Bz-Content-Sha1",
                hex::encode(digest(&SHA1_FOR_LEGACY_USE_ONLY, buf).as_ref()),
            )
            .from_mem(buf)?
            .send()?;

        if !resp.status().is_success() {
            return Err(format!(
                "Failed to upload file: {} {}",
                resp.status(),
                resp.into_string()?
            )
            .into());
        }

        #[derive(Deserialize)]
        struct Response {
            #[serde(rename = "fileId")]
            id: String,
        }

        let resp: Response = resp.json()?;

        Ok(resp.id)
    }
}
