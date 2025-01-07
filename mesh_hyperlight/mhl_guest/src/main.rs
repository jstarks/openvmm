#![allow(unsafe_code)]
#![no_std]
#![no_main]

extern crate alloc;

mod infra;

use alloc::format;
use alloc::string::String;
use mhl_common::InitialMessage;

async fn start(message: InitialMessage) {
    let InitialMessage {
        logger,
        dictionary,
        mut requests,
    } = message;

    while let Ok(req) = requests.recv().await {
        match req {
            mhl_common::Request::TranslateString { request, response } => {
                logger.send(format!("received request: {}", request));

                let result: String = request
                    .chars()
                    .map(|c| dictionary.get(&c).map_or(c, |&c| c))
                    .collect();

                logger.send(format!("sending response: {}", result));
                response.send(result);
            }
            mhl_common::Request::Ping { response } => response.send(()),
        }
    }
}
