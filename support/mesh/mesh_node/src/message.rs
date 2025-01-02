// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Implements the `Message` type.

// UNSAFETY: Needed to define, implement, and call the unsafe extract function.
#![expect(unsafe_code)]

use crate::resource::Resource;
use crate::resource::SerializedMessage;
use mesh_protobuf;
use mesh_protobuf::encoding::BoxEncoding;
use mesh_protobuf::encoding::SerializedMessageEncoder;
use mesh_protobuf::inplace;
use mesh_protobuf::inplace_none;
use mesh_protobuf::protobuf::decode_with;
use mesh_protobuf::protobuf::MessageSizer;
use mesh_protobuf::protobuf::MessageWriter;
use mesh_protobuf::DefaultEncoding;
use mesh_protobuf::MessageDecode;
use mesh_protobuf::MessageEncode;
use std::any::Any;
use std::any::TypeId;
use std::borrow::Cow;
use std::fmt;
use std::fmt::Debug;
use std::mem::MaybeUninit;

/// A message for sending over a channel.
#[derive(Default)]
pub struct OwnedMessage(MessageInner);

enum MessageInner {
    Unserialized(Box<dyn DynSerializeMessage>),
    Serialized(SerializedMessage),
}

impl Debug for OwnedMessage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.pad("OwnedMessage")
    }
}

impl Default for MessageInner {
    fn default() -> Self {
        Self::Serialized(Default::default())
    }
}

impl OwnedMessage {
    /// Serializes the message and returns it.
    pub fn serialize(self) -> SerializedMessage {
        match self.0 {
            MessageInner::Unserialized(_) => SerializedMessage::from_message(self),
            MessageInner::Serialized(message) => message,
        }
    }
}

/// Trait for types that can be constructed as a [`Message`].
///
/// This does not include scalar types such as `u32`, which are encoded as
/// non-message types.
pub trait MeshPayload: DefaultEncoding<Encoding = <Self as MeshPayload>::Encoding> + Sized {
    type Encoding: MessageEncode<Self, Resource>
        + for<'a> MessageDecode<'a, Self, Resource>
        + mesh_protobuf::FieldEncode<Self, Resource>
        + for<'a> mesh_protobuf::FieldDecode<'a, Self, Resource>
        + Send
        + Sync;
}

impl<T> MeshPayload for T
where
    T: DefaultEncoding + Any + Send + 'static,
    T::Encoding: MessageEncode<T, Resource>
        + for<'a> MessageDecode<'a, T, Resource>
        + mesh_protobuf::FieldEncode<T, Resource>
        + for<'a> mesh_protobuf::FieldDecode<'a, T, Resource>
        + Send
        + Sync,
{
    type Encoding = T::Encoding;
}

/// Trait for types that can be a field in a mesh message, including both scalar
/// types and types that implement [`MeshPayload`].
pub trait MeshField: DefaultEncoding<Encoding = <Self as MeshField>::Encoding> + Sized {
    type Encoding: mesh_protobuf::FieldEncode<Self, Resource>
        + for<'a> mesh_protobuf::FieldDecode<'a, Self, Resource>
        + Send
        + Sync;
}

impl<T> MeshField for T
where
    T: DefaultEncoding,
    T::Encoding: mesh_protobuf::FieldEncode<T, Resource>
        + for<'a> mesh_protobuf::FieldDecode<'a, T, Resource>
        + Send
        + Sync,
{
    type Encoding = T::Encoding;
}

/// Trait implemented by concrete messages that can be extracted or serialized
/// into [`SerializedMessage`].
pub trait SerializeMessage: 'static + Send {
    /// The underlying concrete message type.
    type Concrete: Any;

    /// Computes the message size, as in [`MessageEncode::compute_message_size`].
    fn compute_message_size(&mut self, sizer: MessageSizer<'_>);

    /// Writes the message, as in [`MessageEncode::write_message`].
    fn write_message(self, writer: MessageWriter<'_, '_, Resource>);

    /// Extract the concrete message.
    fn extract(self) -> Self::Concrete;
}

/// # Safety
///
/// The implementor must ensure that `extract_or_serialize` initializes the
/// pointer if it returns `Ok(())`.
unsafe trait DynSerializeMessage: Send {
    fn compute_message_size(&mut self, sizer: MessageSizer<'_>);
    fn write_message(self: Box<Self>, writer: MessageWriter<'_, '_, Resource>);

    /// # Safety
    ///
    /// The caller must ensure that `ptr` points to storage whose type matches
    /// `type_id`.
    unsafe fn extract(
        self: Box<Self>,
        type_id: TypeId,
        ptr: *mut (),
    ) -> Result<(), Box<dyn DynSerializeMessage>>;
}

// SAFETY: extract_or_serialize satisfies implementation requirements.
unsafe impl<T: SerializeMessage> DynSerializeMessage for T {
    fn compute_message_size(&mut self, sizer: MessageSizer<'_>) {
        self.compute_message_size(sizer)
    }

    fn write_message(self: Box<Self>, writer: MessageWriter<'_, '_, Resource>) {
        (*self).write_message(writer)
    }

    unsafe fn extract(
        self: Box<Self>,
        type_id: TypeId,
        ptr: *mut (),
    ) -> Result<(), Box<dyn DynSerializeMessage>> {
        if type_id == TypeId::of::<T::Concrete>() {
            // SAFETY: ptr is guaranteed to be T::Concrete by caller.
            unsafe { ptr.cast::<T::Concrete>().write((*self).extract()) };
            Ok(())
        } else {
            Err(self)
        }
    }
}

impl<T: 'static + MeshPayload + Send> SerializeMessage for T {
    type Concrete = Self;

    fn compute_message_size(&mut self, sizer: MessageSizer<'_>) {
        <T as MeshPayload>::Encoding::compute_message_size(self, sizer)
    }

    fn write_message(self, writer: MessageWriter<'_, '_, Resource>) {
        <T as MeshPayload>::Encoding::write_message(self, writer)
    }

    fn extract(self) -> Self::Concrete {
        self
    }
}

impl OwnedMessage {
    /// Creates a new message wrapping `data`, which will be lazily serialized
    /// when needed.
    #[inline]
    pub fn new<T: SerializeMessage>(data: T) -> Self {
        Self(MessageInner::Unserialized(Box::new(data)))
    }

    /// Creates a new message from already-serialized data in `s`.
    pub fn serialized(s: SerializedMessage) -> Self {
        Self(MessageInner::Serialized(s))
    }

    /// Parses the message into a value of type `T`.
    ///
    /// If the message was constructed with `new<T>`, then the round trip
    /// serialization/deserialization is skipped.
    pub fn parse<T: 'static + MeshPayload + Send>(self) -> Result<T, mesh_protobuf::Error> {
        self.try_parse().or_else(|m| m.serialize().into_message())
    }

    pub fn try_parse<T: 'static>(self) -> Result<T, Self> {
        match self.0 {
            MessageInner::Unserialized(m) => {
                let mut message = MaybeUninit::<T>::uninit();
                // SAFETY: calling with appropriately sized and aligned buffer
                // for writing T.
                unsafe {
                    match m.extract(TypeId::of::<T>(), message.as_mut_ptr().cast()) {
                        Ok(()) => Ok(message.assume_init()),
                        Err(message) => Err(Self(MessageInner::Unserialized(message))),
                    }
                }
            }
            MessageInner::Serialized(_) => Err(self),
        }
    }
}

impl DefaultEncoding for OwnedMessage {
    type Encoding = mesh_protobuf::encoding::MessageEncoding<MessageEncoder>;
}

pub struct MessageEncoder;

impl MessageEncode<Box<dyn DynSerializeMessage>, Resource> for MessageEncoder {
    fn write_message(item: Box<dyn DynSerializeMessage>, writer: MessageWriter<'_, '_, Resource>) {
        item.write_message(writer);
    }

    fn compute_message_size(item: &mut Box<dyn DynSerializeMessage>, sizer: MessageSizer<'_>) {
        item.compute_message_size(sizer);
    }
}

impl MessageEncode<OwnedMessage, Resource> for MessageEncoder {
    fn write_message(item: OwnedMessage, writer: MessageWriter<'_, '_, Resource>) {
        match item.0 {
            MessageInner::Unserialized(message) => Self::write_message(message, writer),
            MessageInner::Serialized(message) => {
                SerializedMessageEncoder::write_message(message, writer)
            }
        }
    }

    fn compute_message_size(item: &mut OwnedMessage, sizer: MessageSizer<'_>) {
        match &mut item.0 {
            MessageInner::Unserialized(message) => Self::compute_message_size(message, sizer),
            MessageInner::Serialized(message) => {
                SerializedMessageEncoder::compute_message_size(message, sizer)
            }
        }
    }
}

impl MessageDecode<'_, OwnedMessage, Resource> for MessageEncoder {
    fn read_message(
        item: &mut inplace::InplaceOption<'_, OwnedMessage>,
        reader: mesh_protobuf::protobuf::MessageReader<'_, '_, Resource>,
    ) -> mesh_protobuf::Result<()> {
        let message = item.take().map(OwnedMessage::serialize);
        inplace!(message);
        SerializedMessageEncoder::read_message(&mut message, reader)?;
        item.set(OwnedMessage::serialized(message.take().unwrap()));
        Ok(())
    }
}

enum LocalMessageInner<'a> {
    Owned(OwnedMessage),
    Local(Box<dyn 'a + DynEncodeMessage>),
    View(&'a [u8], Vec<Resource>),
}

pub struct Message<'a>(LocalMessageInner<'a>);

impl<'a> Message<'a> {
    pub fn new<T: SerializeMessage>(data: T) -> Self {
        OwnedMessage::new(data).into()
    }

    pub fn new_local<T: 'a + DefaultEncoding<Encoding = E>, E>(data: T) -> Self
    where
        E: MessageEncode<T, Resource>,
    {
        Self(LocalMessageInner::Local(Box::new(data)))
    }

    pub fn serialized(v: &'a [u8], resources: Vec<Resource>) -> Self {
        Self(LocalMessageInner::View(v, resources))
    }

    pub fn into_owned(self) -> OwnedMessage {
        match self.0 {
            LocalMessageInner::Owned(m) => m,
            LocalMessageInner::Local(_) => {
                OwnedMessage::serialized(SerializedMessage::from_message(self))
            }
            LocalMessageInner::View(v, vec) => OwnedMessage::serialized(SerializedMessage {
                data: v.into(),
                resources: vec,
            }),
        }
    }

    pub fn serialize(self) -> (Cow<'a, [u8]>, Vec<Resource>) {
        match self.0 {
            LocalMessageInner::Owned(OwnedMessage(MessageInner::Serialized(m))) => {
                (Cow::Owned(m.data), m.resources)
            }
            LocalMessageInner::View(data, resources) => (Cow::Borrowed(data), resources),
            m => {
                let m = SerializedMessage::from_message(Self(m));
                (Cow::Owned(m.data), m.resources)
            }
        }
    }

    fn into_data_and_resources(self) -> (Cow<'a, [u8]>, Vec<Option<Resource>>) {
        let (d, r) = self.serialize();
        (d, r.into_iter().map(Some).collect::<Vec<_>>())
    }

    /// Parses the message into a value of type `T`.
    pub fn parse<T: 'static>(mut self) -> Result<T, mesh_protobuf::Error>
    where
        T: DefaultEncoding,
        T::Encoding: for<'b> MessageDecode<'b, T, Resource>,
    {
        if let LocalMessageInner::Owned(m) = self.0 {
            match m.try_parse() {
                Ok(m) => return Ok(m),
                Err(m) => {
                    self = Self(LocalMessageInner::Owned(m));
                }
            }
        }
        self.parse_local()
    }

    /// Parses the message into a value of type `T`.
    pub fn parse_local<T>(self) -> Result<T, mesh_protobuf::Error>
    where
        T: DefaultEncoding,
        T::Encoding: for<'b> MessageDecode<'b, T, Resource>,
    {
        let (data, mut resources) = self.into_data_and_resources();
        inplace_none!(message: T);
        decode_with::<T::Encoding, _, _>(&mut message, &data, &mut resources)?;
        Ok(message.take().expect("should be constructed"))
    }
}

impl From<OwnedMessage> for Message<'_> {
    fn from(m: OwnedMessage) -> Self {
        Self(LocalMessageInner::Owned(m))
    }
}

impl DefaultEncoding for Message<'_> {
    type Encoding = MessageEncoder;
}

impl MessageEncode<Message<'_>, Resource> for MessageEncoder {
    fn write_message(item: Message<'_>, mut writer: MessageWriter<'_, '_, Resource>) {
        match item.0 {
            LocalMessageInner::Owned(m) => Self::write_message(m, writer),
            LocalMessageInner::Local(m) => m.write_message(writer),
            LocalMessageInner::View(data, resources) => {
                writer.raw_message(data, resources);
            }
        }
    }

    fn compute_message_size(item: &mut Message<'_>, mut sizer: MessageSizer<'_>) {
        match &mut item.0 {
            LocalMessageInner::Owned(m) => Self::compute_message_size(m, sizer),
            LocalMessageInner::Local(m) => m.compute_message_size(sizer),
            LocalMessageInner::View(data, resources) => {
                sizer.raw_message(data.len(), resources.len() as u32);
            }
        }
    }
}

trait DynEncodeMessage {
    fn compute_message_size(&mut self, sizer: MessageSizer<'_>);
    fn write_message(self: Box<Self>, writer: MessageWriter<'_, '_, Resource>);
}

impl<T: DefaultEncoding<Encoding = E>, E> DynEncodeMessage for T
where
    E: MessageEncode<T, Resource>,
{
    fn compute_message_size(&mut self, sizer: MessageSizer<'_>) {
        E::compute_message_size(self, sizer);
    }

    fn write_message(self: Box<Self>, writer: MessageWriter<'_, '_, Resource>) {
        BoxEncoding::<E>::write_message(self, writer);
    }
}

#[cfg(test)]
mod tests {
    use super::Message;
    use mesh_protobuf::encoding::ImpossibleField;

    #[test]
    fn roundtrip_without_serialize() {
        #[derive(Debug, Default)]
        struct CantSerialize;
        impl mesh_protobuf::DefaultEncoding for CantSerialize {
            type Encoding = ImpossibleField;
        }

        Message::new(CantSerialize)
            .parse::<CantSerialize>()
            .unwrap();
    }
}
