// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Implements the `Message` type.

// UNSAFETY: Needed to define, implement, and call the unsafe extract function.
#![expect(unsafe_code)]

use crate::resource::Resource;
use crate::resource::SerializedMessage;
use mesh_protobuf;
use mesh_protobuf::DefaultEncoding;
use mesh_protobuf::FieldEncode;
use mesh_protobuf::MessageDecode;
use mesh_protobuf::MessageEncode;
use mesh_protobuf::encoding::SerializedMessageEncoder;
use mesh_protobuf::inplace;
use mesh_protobuf::inplace_none;
use mesh_protobuf::protobuf::MessageSizer;
use mesh_protobuf::protobuf::MessageWriter;
use mesh_protobuf::protobuf::decode_with;
use mesh_protobuf::table::encode::ErasedEncoderEntry;
use std::any::Any;
use std::any::TypeId;
use std::borrow::Cow;
use std::fmt;
use std::fmt::Debug;
use std::marker::PhantomData;
use std::mem::MaybeUninit;

/// A message on a port.
///
/// The message has a static lifetime and is `Send`, so it is appropriate for
/// storing and using across threads.
///
/// See [`Message`] for a version that can reference data with non-static
/// lifetime.
#[derive(Default)]
pub struct OwnedMessage(OwnedMessageInner);

enum OwnedMessageInner {
    Unserialized(Box<dyn DynSerializeMessage>),
    Serialized(SerializedMessage),
}

impl Debug for OwnedMessage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.pad("OwnedMessage")
    }
}

impl Default for OwnedMessageInner {
    fn default() -> Self {
        Self::Serialized(Default::default())
    }
}

impl OwnedMessage {
    /// Serializes the message and returns it.
    pub fn serialize(self) -> SerializedMessage {
        match self.0 {
            OwnedMessageInner::Unserialized(_) => SerializedMessage::from_message(self),
            OwnedMessageInner::Serialized(message) => message,
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
        + FieldEncode<Self, Resource>
        + for<'a> mesh_protobuf::FieldDecode<'a, Self, Resource>
        + Send
        + Sync;
}

impl<T> MeshPayload for T
where
    T: DefaultEncoding + Any + Send + 'static,
    T::Encoding: MessageEncode<T, Resource>
        + for<'a> MessageDecode<'a, T, Resource>
        + FieldEncode<T, Resource>
        + for<'a> mesh_protobuf::FieldDecode<'a, T, Resource>
        + Send
        + Sync,
{
    type Encoding = T::Encoding;
}

/// Trait for types that can be a field in a mesh message, including both scalar
/// types and types that implement [`MeshPayload`].
pub trait MeshField: DefaultEncoding<Encoding = <Self as MeshField>::Encoding> + Sized {
    type Encoding: FieldEncode<Self, Resource>
        + for<'a> mesh_protobuf::FieldDecode<'a, Self, Resource>
        + Send
        + Sync;
}

impl<T> MeshField for T
where
    T: DefaultEncoding,
    T::Encoding: FieldEncode<T, Resource>
        + for<'a> mesh_protobuf::FieldDecode<'a, T, Resource>
        + Send
        + Sync,
{
    type Encoding = T::Encoding;
}

/// Trait implemented by concrete messages that can be extracted or serialized
/// into [`SerializedMessage`].
pub trait SerializeMessage: 'static {
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
unsafe impl<T: SerializeMessage + Send> DynSerializeMessage for T {
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
    pub fn new<T: SerializeMessage + Send>(data: T) -> Self {
        Self(OwnedMessageInner::Unserialized(Box::new(data)))
    }

    /// Creates a new message from already-serialized data in `s`.
    pub fn serialized(s: SerializedMessage) -> Self {
        Self(OwnedMessageInner::Serialized(s))
    }

    /// Parses the message into a value of type `T`.
    ///
    /// If the message was constructed with `new<T>`, then the round trip
    /// serialization/deserialization is skipped.
    pub fn parse<T>(self) -> Result<T, mesh_protobuf::Error>
    where
        T: 'static + DefaultEncoding,
        T::Encoding: for<'a> MessageDecode<'a, T, Resource>,
    {
        Message::from(self).parse()
    }

    /// Tries to unwrap the message into a value of type `T`.
    ///
    /// If the message was not created with [`OwnedMessage::new<T>`], then this
    /// returns `Err(self)`.
    //
    // FUTURE: remove this optimization once nothing depends on it for
    // functionality or performance.
    pub fn try_unwrap<T: 'static>(self) -> Result<T, Self> {
        match self.0 {
            OwnedMessageInner::Unserialized(m) => {
                let mut message = MaybeUninit::<T>::uninit();
                // SAFETY: calling with appropriately sized and aligned buffer
                // for writing T.
                unsafe {
                    match m.extract(TypeId::of::<T>(), message.as_mut_ptr().cast()) {
                        Ok(()) => Ok(message.assume_init()),
                        Err(message) => Err(Self(OwnedMessageInner::Unserialized(message))),
                    }
                }
            }
            OwnedMessageInner::Serialized(_) => Err(self),
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
            OwnedMessageInner::Unserialized(message) => Self::write_message(message, writer),
            OwnedMessageInner::Serialized(message) => {
                SerializedMessageEncoder::write_message(message, writer)
            }
        }
    }

    fn compute_message_size(item: &mut OwnedMessage, sizer: MessageSizer<'_>) {
        match &mut item.0 {
            OwnedMessageInner::Unserialized(message) => Self::compute_message_size(message, sizer),
            OwnedMessageInner::Serialized(message) => {
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
        item.set(OwnedMessage(OwnedMessageInner::Serialized(
            message.take().unwrap(),
        )));
        Ok(())
    }
}

/// A message on a port.
///
/// The message may reference data with non-static lifetime, and it may not be
/// [`Send`]. See [`OwnedMessage`] for a version that is [`Send`].
pub struct Message<'a>(MessageInner<'a>);

impl Debug for Message<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.pad("Message")
    }
}

enum MessageInner<'a> {
    Owned(OwnedMessage),
    StackOneofVariant(StackOneofVariantMessage<'a>),
    View(&'a [u8], Vec<Resource>),
}

impl<'a> Message<'a> {
    /// Returns a new instance wrapping `message`. The message will be boxed and
    /// will be lazily serialized when needed.
    pub fn new<T: SerializeMessage + Send>(message: T) -> Self {
        OwnedMessage::new(message).into()
    }

    /// Returns a new message that encodes as a oneof variant with the given
    /// field number. The given encoder is used to encode the field.
    ///
    /// # Safety
    /// The caller must ensure that `ptr` remains valid for the lifetime of the
    /// message and that the encoder matches the type of the message. The
    /// message takes ownership of the value pointed to by `ptr` (but not the
    /// underlying storage), so the caller must ensure that the value is never
    /// used again.
    pub unsafe fn new_erased_oneof_variant_message(
        field_number: u32,
        ptr: *mut (),
        encoder: ErasedEncoderEntry,
    ) -> Self {
        Message(MessageInner::StackOneofVariant(StackOneofVariantMessage {
            ptr,
            field_number,
            encoder,
            _phantom: PhantomData,
        }))
    }

    /// Helper for [`stack_oneof_variant_message!`].
    ///
    /// # Safety
    /// The caller must ensure that `message` is initialized. It will be dropped
    /// in place when the message is dropped, so it must not be used again.
    #[doc(hidden)]
    pub unsafe fn new_stack_oneof_variant<T: 'a + DefaultEncoding>(
        field_number: u32,
        message: &'a mut MaybeUninit<T>,
    ) -> Self
    where
        T::Encoding: FieldEncode<T, Resource>,
    {
        unsafe {
            Self::new_erased_oneof_variant_message(
                field_number,
                message.as_mut_ptr().cast(),
                T::Encoding::ENTRY.erase(),
            )
        }
    }

    /// Returns an instance for a serialized message with `data` and
    /// `resources`.
    pub fn serialized(data: &'a [u8], resources: Vec<Resource>) -> Self {
        Self(MessageInner::View(data, resources))
    }

    /// Converts the message into an [`OwnedMessage`].
    ///
    /// If the message was created with [`Message::new`] or
    /// [`From<OwnedMessage>`], then this operation is cheap. Otherwise, this
    /// operation will serialize the message and allocate a new buffer.
    pub fn into_owned(self) -> OwnedMessage {
        let m = match self.0 {
            MessageInner::Owned(m) => return m,
            MessageInner::StackOneofVariant(_) => SerializedMessage::from_message(self),
            MessageInner::View(v, vec) => SerializedMessage {
                data: v.into(),
                resources: vec,
            },
        };
        OwnedMessage(OwnedMessageInner::Serialized(m))
    }

    /// Serializes the message and returns it.
    ///
    /// If the message is already serialized, then this is a cheap operation.
    pub fn serialize(self) -> (Cow<'a, [u8]>, Vec<Resource>) {
        let m = match self.0 {
            MessageInner::View(data, resources) => return (Cow::Borrowed(data), resources),
            MessageInner::Owned(OwnedMessage(OwnedMessageInner::Serialized(m))) => m,
            m => SerializedMessage::from_message(Self(m)),
        };
        (Cow::Owned(m.data), m.resources)
    }

    fn into_data_and_resources(self) -> (Cow<'a, [u8]>, Vec<Option<Resource>>) {
        let (d, r) = self.serialize();
        (d, r.into_iter().map(Some).collect::<Vec<_>>())
    }

    /// Parses the message into a value of type `T`.
    ///
    /// If the message was constructed with `new<T>`, then the round trip
    /// serialization/deserialization is skipped.
    pub fn parse<T>(mut self) -> Result<T, mesh_protobuf::Error>
    where
        T: 'static + DefaultEncoding,
        T::Encoding: for<'b> MessageDecode<'b, T, Resource>,
    {
        if let MessageInner::Owned(m) = self.0 {
            match m.try_unwrap() {
                Ok(m) => return Ok(m),
                Err(m) => {
                    self = Self(MessageInner::Owned(m));
                }
            }
        }
        self.parse_non_static()
    }

    /// Parses the message into a value of type `T`.
    ///
    /// When `T` has static lifetime, prefer [`Message::parse`] instead, since
    /// it can recover a `T` passed to [`Message::new`] without round-trip
    /// serialization.
    pub fn parse_non_static<T>(self) -> Result<T, mesh_protobuf::Error>
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
        Self(MessageInner::Owned(m))
    }
}

impl DefaultEncoding for Message<'_> {
    type Encoding = mesh_protobuf::encoding::MessageEncoding<MessageEncoder>;
}

impl MessageEncode<Message<'_>, Resource> for MessageEncoder {
    fn write_message(item: Message<'_>, mut writer: MessageWriter<'_, '_, Resource>) {
        match item.0 {
            MessageInner::Owned(m) => Self::write_message(m, writer),
            MessageInner::StackOneofVariant(m) => m.write_message(writer),
            MessageInner::View(data, resources) => {
                writer.raw_message(data, resources);
            }
        }
    }

    fn compute_message_size(item: &mut Message<'_>, mut sizer: MessageSizer<'_>) {
        match &mut item.0 {
            MessageInner::Owned(m) => Self::compute_message_size(m, sizer),
            MessageInner::StackOneofVariant(m) => m.compute_message_size(sizer),
            MessageInner::View(data, resources) => {
                sizer.raw_message(data.len(), resources.len() as u32);
            }
        }
    }
}

/// Returns a [`Message`] representing a oneof variant with the given field
/// number and field value.
///
/// This takes ownership of a value but leaves the value in place on the stack,
/// eliminating the need for a heap allocation.
#[macro_export]
macro_rules! stack_oneof_variant_message {
    ($field_number:expr, $v:expr) => {
        (|v| {
            // UNSAFETY: required to call unsafe function.
            #[expect(unsafe_code)]
            {
                // SAFETY: The value is initialized and never used again.
                unsafe { $crate::message::Message::new_stack_oneof_variant($field_number, v) }
            }
        })(&mut ::core::mem::MaybeUninit::new($v))
    };
}

/// A message whose storage is on the stack.
struct StackOneofVariantMessage<'a> {
    ptr: *mut (),
    field_number: u32,
    encoder: ErasedEncoderEntry,
    _phantom: PhantomData<&'a mut ()>,
}

impl Drop for StackOneofVariantMessage<'_> {
    fn drop(&mut self) {
        // SAFETY: The value is owned.
        unsafe { self.encoder.drop_field(self.ptr.cast()) }
    }
}

impl StackOneofVariantMessage<'_> {
    fn compute_message_size(&mut self, mut sizer: MessageSizer<'_>) {
        // SAFETY: The value is owned and the encoder type matches.
        unsafe {
            self.encoder.compute_size_field::<Resource>(
                self.ptr.cast(),
                sizer.field(self.field_number).sequence().field(),
            );
        }
    }

    fn write_message(self, mut writer: MessageWriter<'_, '_, Resource>) {
        let Self {
            ptr,
            field_number,
            encoder,
            ..
        } = self;
        std::mem::forget(self);
        // SAFETY: The value is owned and the encoder type matches.
        unsafe { encoder.write_field(ptr.cast(), writer.field(field_number).sequence().field()) }
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
