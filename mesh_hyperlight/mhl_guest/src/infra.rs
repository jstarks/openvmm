use alloc::borrow::ToOwned;
use alloc::boxed::Box;
use alloc::vec;
use alloc::vec::Vec;
use core::cell::RefCell;
use core::future::Future;
use core::pin::Pin;
use core::ptr::addr_of;
use core::task::Context;
use futures::task::noop_waker_ref;
use futures::FutureExt;
use getrandom::register_custom_getrandom;
use hyperlight_common::flatbuffer_wrappers::function_call::FunctionCall;
use hyperlight_common::flatbuffer_wrappers::function_types::ParameterValue;
use hyperlight_common::flatbuffer_wrappers::function_types::ReturnType;
use hyperlight_common::flatbuffer_wrappers::guest_error::ErrorCode;
use hyperlight_common::flatbuffer_wrappers::util::get_flatbuffer_result_from_void;
use hyperlight_guest as _;
use hyperlight_guest::error::HyperlightGuestError;
use hyperlight_guest::host_function_call::call_host_function;
use mesh_node::common::NodeId;
use mesh_node::local_node::LocalNode;
use mesh_node::local_node::RemoteNodeHandle;
use mesh_node::local_node::SendEvent;
use mesh_protobuf::decode;
use mhl_common::NullConnector;
use mhl_common::StartParams;

struct State {
    node: LocalNode,
    remote_node_id: NodeId,
    _remote: RemoteNodeHandle,
    future: Option<Pin<Box<dyn Future<Output = ()>>>>,
}

static mut STATE: RefCell<Option<State>> = RefCell::new(None);

#[unsafe(no_mangle)]
pub extern "C" fn hyperlight_main() {}

#[unsafe(no_mangle)]
pub fn guest_dispatch_function(
    function_call: FunctionCall,
) -> Result<Vec<u8>, HyperlightGuestError> {
    match function_call.function_name.as_str() {
        "start" => {
            let params: Vec<u8> = function_call
                .parameters
                .unwrap()
                .into_iter()
                .next()
                .unwrap()
                .try_into()
                .unwrap();
            let params = decode::<StartParams>(&params).unwrap();
            let node = LocalNode::with_id(params.local.node, Box::new(NullConnector));
            let remote = node.add_remote(params.remote.node);
            let port = node.add_port(params.local.port, params.remote);
            remote.connect(Connection);
            let mut state = unsafe { &*addr_of!(STATE) }.borrow_mut();
            *state = Some(State {
                node,
                _remote: remote,
                remote_node_id: params.remote.node,
                future: Some(Box::pin(crate::start(port.into()))),
            });
        }
        "send" => {
            let data: Vec<u8> = function_call
                .parameters
                .unwrap()
                .drain(..)
                .next()
                .unwrap()
                .try_into()
                .unwrap();
            let mut state = unsafe { &*addr_of!(STATE) }.borrow_mut();
            let state = state.as_mut().unwrap();
            state
                .node
                .event(&state.remote_node_id, &data, &mut Vec::new());
            if let Some(fut) = &mut state.future {
                if fut
                    .poll_unpin(&mut Context::from_waker(noop_waker_ref()))
                    .is_ready()
                {
                    state.future = None;
                }
            }
        }
        _ => {
            return Err(HyperlightGuestError::new(
                ErrorCode::GuestFunctionNotFound,
                "Function not found".to_owned(),
            ))
        }
    }
    Ok(get_flatbuffer_result_from_void())
}

struct Connection;

impl SendEvent for Connection {
    fn event(&self, event: mesh_node::local_node::OutgoingEvent<'_>) {
        let mut v = Vec::with_capacity(event.len());
        event.write_to(&mut v, &mut Vec::new());
        call_host_function(
            "send",
            Some(vec![ParameterValue::VecBytes(v)]),
            ReturnType::Void,
        )
        .unwrap();
    }
}

register_custom_getrandom!(host_getrandom);

fn host_getrandom(buf: &mut [u8]) -> Result<(), getrandom::Error> {
    call_host_function(
        "getrandom",
        Some(vec![ParameterValue::ULong(buf.len() as u64)]),
        ReturnType::VecBytes,
    )
    .unwrap();
    Ok(())
}
