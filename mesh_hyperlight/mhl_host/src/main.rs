mod infra;

use futures_concurrency::future::Race;
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
    let (send, recv) = mesh::oneshot();

    let (logger_send, mut logger_recv) = mesh::channel();
    let (req_send, req_recv) = mesh::channel();
    send.send(mhl_common::InitialMessage {
        logger: logger_send,
        dictionary: [('h', 'H'), ('w', 'W')].into_iter().collect(),
        requests: req_recv,
    });

    let sandbox_task = async {
        sandbox.run(recv).await?;
        anyhow::Ok(())
    };

    let log_task = async {
        while let Ok(msg) = logger_recv.recv().await {
            println!("guest: {}", msg);
        }
        Ok(())
    };

    let work_task = async {
        let (response_send, response_recv) = mesh::oneshot();
        req_send.send(mhl_common::Request {
            request: "hello world".to_owned(),
            response: response_send,
        });
        println!("got response: {}", response_recv.await?);
        Ok(())
    };

    futures::executor::block_on((sandbox_task, log_task, work_task).race())?;
    Ok(())
}
