// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! OpenVMM GUI frontend.
//!
//! Opens an Iced window using the tiny-skia software renderer to display the
//! VM framebuffer and forward keyboard/mouse input. Designed to run in a child
//! process spawned via `mesh_process::launch_host`.

#![forbid(unsafe_code)]

use framebuffer::FramebufferAccess;
use iced::Element;
use iced::Task;
use iced::Theme;
use parking_lot::Mutex;

/// Run the GUI. This blocks until the window is closed.
pub fn run(
    framebuffer: FramebufferAccess,
    input_send: mesh::Sender<input_core::InputData>,
    alive_send: mesh::Sender<()>,
) -> anyhow::Result<()> {
    tracing::info!("GUI starting");

    // Wrap in Mutex so the boot closure can be Fn (iced requires this).
    // The closure will only be called once in practice.
    let params = Mutex::new(Some((framebuffer, input_send, alive_send)));

    iced::application(
        move || {
            let (framebuffer, input_send, alive_send) =
                params.lock().take().expect("boot called once");
            (
                App {
                    _framebuffer: framebuffer,
                    _input_send: input_send,
                    _alive_send: alive_send,
                },
                Task::none(),
            )
        },
        App::update,
        App::view,
    )
    .theme(App::theme)
    .window_size((800.0, 600.0))
    .run()
    .map_err(|e| anyhow::anyhow!("iced application error: {e}"))?;

    tracing::info!("GUI exiting");
    Ok(())
}

struct App {
    _framebuffer: FramebufferAccess,
    _input_send: mesh::Sender<input_core::InputData>,
    _alive_send: mesh::Sender<()>,
}

#[derive(Debug, Clone)]
enum Message {}

impl App {
    fn update(&mut self, _message: Message) -> Task<Message> {
        Task::none()
    }

    fn view(&self) -> Element<'_, Message> {
        iced::widget::text("OpenVMM GUI - Connected").into()
    }

    fn theme(&self) -> Theme {
        Theme::Dark
    }
}
