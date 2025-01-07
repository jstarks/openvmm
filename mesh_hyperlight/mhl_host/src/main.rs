mod infra;

use futures_concurrency::future::TryJoin;
use hyperlight_host::sandbox::uninitialized::UninitializedSandbox;
use hyperlight_host::GuestBinary;

fn main() -> anyhow::Result<()> {
    let guest_path = "target/x86_64-unknown-none/debug/mhl_guest";

    let usandbox = UninitializedSandbox::new(
        GuestBinary::FilePath(guest_path.to_owned()),
        None,
        None,
        None,
    )?;

    let sandbox = infra::HyperlightMeshSandbox::new(usandbox)?;

    let (logger_send, mut logger_recv) = mesh::channel();
    let (req_send, req_recv) = mesh::channel();

    let sandbox_task = sandbox.run(mhl_common::InitialMessage {
        logger: logger_send,
        requests: req_recv,
        dictionary: [('h', 'H'), ('w', 'W')].into_iter().collect(),
    });

    let log_task = async {
        while let Ok(msg) = logger_recv.recv().await {
            println!("guest: {}", msg);
        }
        Ok(())
    };

    let work_task = async {
        let (response_send, response_recv) = mesh::oneshot();
        req_send.send(mhl_common::Request::Ping {
            response: response_send,
        });
        response_recv.await?;
        println!("ping successful");

        for s in ["hello world", "what's up"] {
            let (response_send, response_recv) = mesh::oneshot();
            req_send.send(mhl_common::Request::TranslateString {
                request: s.to_owned(),
                response: response_send,
            });
            let response = response_recv.await?;
            println!("got response: {response}");
        }
        drop(req_send);
        Ok(())
    };

    futures::executor::block_on((sandbox_task, log_task, work_task).try_join())?;
    Ok(())
}
