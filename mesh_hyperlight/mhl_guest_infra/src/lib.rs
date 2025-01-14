#![no_std]
#![allow(unsafe_code)]

extern crate alloc;

use alloc::borrow::ToOwned;
use alloc::boxed::Box;
use alloc::vec;
pub use alloc::vec::Vec;
use core::cell::RefCell;
use core::future::Future;
use core::pin::Pin;
use core::ptr::addr_of;
use core::task::Context;
use futures::task::noop_waker_ref;
use futures::FutureExt;
use getrandom::register_custom_getrandom;
pub use hyperlight_common::flatbuffer_wrappers::function_call::FunctionCall;
use hyperlight_common::flatbuffer_wrappers::function_types::ParameterType;
use hyperlight_common::flatbuffer_wrappers::function_types::ParameterValue;
use hyperlight_common::flatbuffer_wrappers::function_types::ReturnType;
use hyperlight_common::flatbuffer_wrappers::guest_error::ErrorCode;
use hyperlight_common::flatbuffer_wrappers::util::get_flatbuffer_result_from_int;
pub use hyperlight_common::flatbuffer_wrappers::util::get_flatbuffer_result_from_vec;
use hyperlight_common::flatbuffer_wrappers::util::get_flatbuffer_result_from_void;
use hyperlight_guest as _;
pub use hyperlight_guest::error::HyperlightGuestError;
use hyperlight_guest::guest_function_definition::GuestFunctionDefinition;
use hyperlight_guest::guest_function_register::register_function;
pub use hyperlight_guest::host_function_call::call_host_function;
use hyperlight_guest::host_function_call::get_host_value_return_as_vecbytes;
use mesh_channel_core::OneshotReceiver;
use mesh_node::common::NodeId;
use mesh_node::local_node::LocalNode;
use mesh_node::local_node::RemoteNodeHandle;
use mesh_node::local_node::SendEvent;
use mesh_node::message::MeshField;
pub use mesh_protobuf;
use mesh_protobuf::decode;
use mesh_protobuf::DefaultEncoding;
use mesh_protobuf::MessageDecode;
use mesh_protobuf::MessageEncode;
use mesh_protobuf::NoResources;
use mhl_common::infra::NullConnector;
use mhl_common::infra::StartParams;

struct State {
    node: LocalNode,
    remote_node_id: NodeId,
    _remote: RemoteNodeHandle,
    future: Option<Pin<Box<dyn Future<Output = ()>>>>,
}

static mut STATE: RefCell<Option<State>> = RefCell::new(None);

#[macro_export]
macro_rules! mesh_hyperlight {
    ($start:expr) => {
        #[unsafe(no_mangle)]
        pub extern "C" fn hyperlight_main() {}

        #[unsafe(no_mangle)]
        pub fn guest_dispatch_function(
            function_call: $crate::FunctionCall,
        ) -> Result<$crate::Vec<u8>, $crate::HyperlightGuestError> {
            $crate::guest_dispatch_function($start, function_call)
        }
    };
}

pub fn guest_dispatch_function<T, Fut>(
    start: impl 'static + FnOnce(T) -> Fut,
    function_call: FunctionCall,
) -> Result<Vec<u8>, HyperlightGuestError>
where
    T: MeshField,
    Fut: 'static + Future<Output = ()>,
{
    let mut state = unsafe { &*addr_of!(STATE) }.borrow_mut();
    let state = &mut *state;

    let param = function_call
        .parameters
        .as_ref()
        .and_then(|p| p.get(0))
        .ok_or_else(|| {
            HyperlightGuestError::new(
                ErrorCode::GuestFunctionIncorrecNoOfParameters,
                "invalid parameters".to_owned(),
            )
        })?;

    let ParameterValue::VecBytes(input) = param else {
        return Err(HyperlightGuestError::new(
            ErrorCode::GuestFunctionParameterTypeMismatch,
            "invalid parameters".to_owned(),
        ));
    };

    let r = match function_call.function_name.as_str() {
        "start" => {
            let params = decode::<StartParams>(input).unwrap();
            let node = LocalNode::with_id(params.local.node, Box::new(NullConnector));
            let remote = node.add_remote(params.remote.node);
            let port = node.add_port(params.local.port, params.remote);
            remote.connect(Connection);
            let future = async move {
                let message = OneshotReceiver::from(port).await.unwrap();
                start(message).await
            };
            *state = Some(State {
                node,
                _remote: remote,
                remote_node_id: params.remote.node,
                future: Some(Box::pin(future)),
            });
            get_flatbuffer_result_from_void()
        }
        "send" => {
            let state = state.as_mut().ok_or_else(|| {
                HyperlightGuestError::new(ErrorCode::GuestError, "failed to call start".to_owned())
            })?;

            state
                .node
                .event(&state.remote_node_id, input, &mut Vec::new());

            if let Some(fut) = &mut state.future {
                if fut
                    .poll_unpin(&mut Context::from_waker(noop_waker_ref()))
                    .is_ready()
                {
                    state.future = None;
                }
            }

            get_flatbuffer_result_from_int(state.future.is_some() as i32)
        }
        _ => {
            return Err(HyperlightGuestError::new(
                ErrorCode::GuestFunctionNotFound,
                "Function not found".to_owned(),
            ))
        }
    };
    Ok(r)
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

pub fn call_protobuf_host_function<T, R>(name: &str, value: T) -> R
where
    T: DefaultEncoding,
    T::Encoding: MessageEncode<T, NoResources>,
    R: DefaultEncoding,
    R::Encoding: for<'a> MessageDecode<'a, R, NoResources>,
{
    call_host_function(
        name,
        Some(vec![ParameterValue::VecBytes(mesh_protobuf::encode(value))]),
        ReturnType::VecBytes,
    )
    .unwrap();
    let result = get_host_value_return_as_vecbytes().unwrap();
    decode(&result).unwrap()
}

pub fn register_protobuf_guest_function(
    name: &str,
    f: fn(&FunctionCall) -> Result<Vec<u8>, HyperlightGuestError>,
) {
    register_function(GuestFunctionDefinition {
        function_name: name.to_owned(),
        parameter_types: vec![ParameterType::VecBytes],
        return_type: ReturnType::VecBytes,
        function_pointer: f as usize as i64,
    })
}

#[macro_export]
macro_rules! guest_func {
    ($name:ident) => {
        $crate::register_protobuf_guest_function(stringify!($name), |func| {
            let input: Vec<u8> = func
                .parameters
                .clone()
                .unwrap()
                .into_iter()
                .next()
                .unwrap()
                .try_into()
                .unwrap();
            let value = $crate::mesh_protobuf::decode(&input).unwrap();
            let result = $name(value);
            let result = $crate::mesh_protobuf::encode((result,));
            Ok($crate::get_flatbuffer_result_from_vec(&result))
        });
    };
}

#[macro_export]
macro_rules! host_func {
    ($vis:vis fn $name:ident($($arg:ident: $arg_ty:ty),* $(,)?) -> $ret:ty;) => {
        $vis fn $name($($arg: $arg_ty,)*) -> $ret {
            let (r,) = $crate::call_protobuf_host_function(
                stringify!($name),
                ($($arg,)*),
            );
            r
        }
    }
}
