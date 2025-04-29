//! Common global configuration.

use flowey::node::prelude::*;

flowey_config! {
    /// Automatically install tools if they are not found.
    #[derive(Default)]
    pub struct AutoInstall(pub bool);

    /// Interact with the user on the terminal for things like installing
    /// packages.
    #[derive(Default)]
    pub struct Interactive(pub bool);

    /// Write verbose output.
    #[derive(Default)]
    pub struct Verbose(pub ReadVar<bool>);

    /// Do not update packages in package managers such as cargo.
    pub struct PackagesLocked(pub bool);
}
