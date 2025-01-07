use futures_concurrency::future::TryJoin;
use hyperlight_host::func::HostFunction1;
use hyperlight_host::func::ParameterValue;
use hyperlight_host::func::ReturnType;
use hyperlight_host::func::ReturnValue;
use hyperlight_host::sandbox_state::sandbox::EvolvableSandbox;
use hyperlight_host::sandbox_state::transition::Noop;
use hyperlight_host::MultiUseGuestCallContext;
use hyperlight_host::MultiUseSandbox;
use hyperlight_host::UninitializedSandbox;
use mesh::local_node::LocalNode;
use mesh::local_node::SendEvent;
use mesh::message::MeshField;
use mesh::Address;
use mesh::NodeId;
use mesh::PortId;
use mhl_common::infra::NullConnector;
use mhl_common::infra::StartParams;
use std::sync::Arc;
use std::sync::Mutex;

pub struct HyperlightMeshSandbox {
    context: MultiUseGuestCallContext,
    guest_recv: mesh::Receiver<Vec<u8>>,
}

impl HyperlightMeshSandbox {
    pub fn new(mut usandbox: UninitializedSandbox) -> hyperlight_host::Result<Self> {
        fn getrandom(n: u64) -> hyperlight_host::Result<Vec<u8>> {
            let mut v = vec![0u8; n as usize];
            getrandom::getrandom(&mut v).unwrap();
            Ok(v)
        }

        let (guest_send, guest_recv) = mesh::channel();

        let send = Arc::new(Mutex::new(move |v: Vec<u8>| {
            guest_send.send(v);
            Ok(())
        }));
        send.register(&mut usandbox, "send")?;

        let getrandom = Arc::new(Mutex::new(getrandom));
        getrandom.register(&mut usandbox, "getrandom")?;
        let sbox = usandbox.evolve(Noop::<UninitializedSandbox, MultiUseSandbox>::default())?;
        let context = sbox.new_call_context();
        Ok(Self {
            context,
            guest_recv,
        })
    }

    pub async fn run(mut self, message: impl MeshField) -> anyhow::Result<()> {
        let guest_address = Address::new(NodeId::new(), PortId::new());
        let host_address = Address::new(NodeId::new(), PortId::new());
        let params = StartParams {
            local: guest_address,
            remote: host_address,
        };
        let node = LocalNode::with_id(host_address.node, Box::new(NullConnector));
        let remote = node.add_remote(guest_address.node);
        let port = node.add_port(host_address.port, guest_address);
        mesh::OneshotSender::from(port).send(message);

        self.context.call(
            "start",
            ReturnType::Void,
            Some(vec![ParameterValue::VecBytes(mesh_protobuf::encode(
                params,
            ))]),
        )?;

        let (host_send, mut host_recv) = mesh::channel();
        remote.connect(Connection(host_send));

        let guest_send_task = async {
            while let Ok(v) = self.guest_recv.recv().await {
                node.event(&guest_address.node, v.as_slice(), &mut Vec::new());
            }
            Ok(())
        };

        let host_send_task = async {
            while let Ok(v) = host_recv.recv().await {
                let r = self.context.call(
                    "send",
                    ReturnType::Int,
                    Some(vec![ParameterValue::VecBytes(v)]),
                )?;
                let ReturnValue::Int(r) = r else {
                    anyhow::bail!("unexpected return value")
                };
                if r == 0 {
                    break;
                }
            }
            remote.disconnect();
            drop(self.context);
            drop(remote);
            Ok(())
        };

        (guest_send_task, host_send_task).try_join().await?;
        Ok(())
    }
}

struct Connection(mesh::Sender<Vec<u8>>);

impl SendEvent for Connection {
    fn event(&self, event: mesh::local_node::OutgoingEvent<'_>) {
        let mut v = Vec::with_capacity(event.len());
        event.write_to(&mut v, &mut Vec::new());
        self.0.send(v);
    }
}
