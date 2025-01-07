#![allow(unsafe_code)]
#![no_std]
#![no_main]

extern crate alloc;

mod infra;

use alloc::format;
use alloc::string::String;
use mesh_channel_core::OneshotReceiver;
use mhl_common::InitialMessage;

async fn start(recv: OneshotReceiver<InitialMessage>) {
    let InitialMessage {
        logger,
        dictionary,
        mut requests,
    } = recv.await.unwrap();

    while let Ok(req) = requests.recv().await {
        logger.send(format!("received request: {}", req.request));

        let result: String = req
            .request
            .chars()
            .map(|c| dictionary.get(&c).map_or(c, |&c| c))
            .collect();

        logger.send(format!("sending response: {}", result));
        req.response.send(result);
    }
}
