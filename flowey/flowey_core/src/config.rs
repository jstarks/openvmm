//! Types for job configuration.

use serde::Deserialize;
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde::ser::SerializeMap;
use std::any::Any;
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::rc::Rc;

/// A trait for types that can be used as node configuration.
pub trait NodeConfig: Any + Serialize + DeserializeOwned {
    #[doc(hidden)]
    fn config_name() -> &'static str;

    #[expect(non_snake_case)]
    #[doc(hidden)]
    fn do_not_manually_impl_this_trait__use_the_flowey_config_macro_instead();
}

trait DynConfig: Any {
    fn serialize(&self) -> serde_json::Value;
    fn into_rc(self: Box<Self>) -> Rc<dyn DynConfig>;
}

impl std::fmt::Debug for dyn DynConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.serialize().fmt(f)
    }
}

impl<T: NodeConfig> DynConfig for T {
    fn serialize(&self) -> serde_json::Value {
        serde_json::to_value(self).unwrap()
    }

    fn into_rc(self: Box<Self>) -> Rc<dyn DynConfig> {
        Rc::new(*self)
    }
}

#[derive(Default)]
pub struct ConfigBuilder(BTreeMap<&'static str, Box<dyn DynConfig>>);

impl ConfigBuilder {
    pub(crate) fn replace<T: NodeConfig>(&mut self, value: T) -> Option<T> {
        self.0.insert(T::config_name(), Box::new(value)).map(|v| {
            *(v as Box<dyn Any>)
                .downcast()
                .unwrap_or_else(|_| panic!("duplicate config names involving {}", T::config_name()))
        })
    }

    pub(crate) fn get_mut<T: NodeConfig + Default>(&mut self) -> &mut T {
        let v = self
            .0
            .entry(T::config_name())
            .or_insert_with(|| Box::new(T::default()));

        (v.as_mut() as &mut dyn Any)
            .downcast_mut()
            .expect("duplicate config names")
    }

    pub fn build(self) -> ConfigMap {
        ConfigMap(Rc::new(RefCell::new(
            self.0
                .into_iter()
                .map(|(k, v)| (k.to_owned(), ConfigEntry::Value(v.into_rc())))
                .collect(),
        )))
    }
}

/// A map containing stable configuration values.
#[derive(Debug, Clone, Default)]
pub struct ConfigMap(Rc<RefCell<BTreeMap<String, ConfigEntry>>>);

#[derive(Debug)]
enum ConfigEntry {
    Json(serde_json::Value),
    Value(Rc<dyn DynConfig>),
}

impl ConfigMap {
    pub(crate) fn get<T: NodeConfig + Default>(&self) -> Rc<T> {
        let mut config = self.0.borrow_mut();
        config
            .entry(T::config_name().into())
            .or_insert_with(|| ConfigEntry::Value(Rc::new(T::default())))
            .value()
    }

    pub(crate) fn try_get<T: NodeConfig>(&self) -> Option<Rc<T>> {
        let mut config = self.0.borrow_mut();
        Some(config.get_mut(T::config_name())?.value())
    }
}

impl ConfigEntry {
    fn value<T: NodeConfig>(&mut self) -> Rc<T> {
        match self {
            ConfigEntry::Json(items) => {
                let v = Rc::new(T::deserialize(&*items).unwrap());
                *self = ConfigEntry::Value(v.clone());
                v
            }
            ConfigEntry::Value(any) => Rc::downcast(any.clone()).ok().unwrap(),
        }
    }
}

impl Serialize for ConfigMap {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let v = self.0.borrow();
        let mut map = serializer.serialize_map(Some(v.len()))?;
        for (k, v) in v.iter() {
            let buf;
            let v = match v {
                ConfigEntry::Json(v) => v,
                ConfigEntry::Value(v) => {
                    buf = v.serialize();
                    &buf
                }
            };
            map.serialize_entry(k, v)?;
        }
        map.end()
    }
}

impl<'de> Deserialize<'de> for ConfigMap {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let v = BTreeMap::<_, _>::deserialize(deserializer)?;
        Ok(ConfigMap(Rc::new(RefCell::new(
            v.into_iter()
                .map(|(k, v)| (k, ConfigEntry::Json(v)))
                .collect(),
        ))))
    }
}

#[macro_export]
macro_rules! flowey_config {
    () => {};
    (
        $(#[$a:meta])*
        $vis:vis struct $config:ident {
            $($tt:tt)*
        }
        $($rest:tt)*
    ) => {
        $crate::flowey_config!{ @impl $config;
            $(#[$a])*
            $vis struct $config {
                $($tt)*
            }
        }
        $crate::flowey_config!($($rest)*);
    };
    (
        $(#[$a:meta])*
        $vis:vis struct $config:ident($($tt:tt)*);
        $($rest:tt)*
    ) => {
        $crate::flowey_config!{ @impl $config;
            $(#[$a])*
            $vis struct $config($($tt)*);
        }
        $crate::flowey_config!($($rest)*);
    };
    (@impl $config:ident; $item:item) => {
        #[derive($crate::reexports::Serialize, $crate::reexports::Deserialize)]
        $item

        impl $crate::config::NodeConfig for $config {
            fn config_name() -> &'static str {
                concat!(module_path!(), "::", stringify!($config))
            }

            fn do_not_manually_impl_this_trait__use_the_flowey_config_macro_instead() {}
        }
    }
}
