// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! OpenVMM GUI frontend.
//!
//! Opens an Iced window using the tiny-skia software renderer to display the
//! VM framebuffer and forward keyboard/mouse input. Designed to run in a child
//! process spawned via `mesh_process::launch_host`.

#![forbid(unsafe_code)]

use framebuffer::FramebufferAccess;
use framebuffer::View;
use iced::Element;
use iced::Length;
use iced::Subscription;
use iced::Task;
use iced::Theme;
use iced::exit;
use iced::widget::column;
use iced::widget::container;
use iced::widget::image;
use iced::widget::row;
use iced::widget::text;
use parking_lot::Mutex;
use std::time::Duration;
use std::time::Instant;

/// Run the GUI. This blocks until the window is closed.
pub fn run(
    framebuffer: FramebufferAccess,
    input_send: mesh::Sender<input_core::InputData>,
    alive_send: mesh::Sender<()>,
) -> anyhow::Result<()> {
    tracing::info!("GUI starting");

    let view = framebuffer
        .view()
        .map_err(|e| anyhow::anyhow!("failed to map framebuffer: {e}"))?;

    // Wrap in Mutex so the boot closure can be Fn (iced requires this).
    // The closure will only be called once in practice.
    let params = Mutex::new(Some((view, input_send, alive_send)));

    iced::application(
        move || {
            let (mut view, input_send, alive_send) =
                params.lock().take().expect("boot called once");

            // Read the first frame eagerly so the display is immediately
            // populated instead of showing "Waiting for framebuffer".
            let (w, h) = view.resolution();
            let (w, h) = (w as u32, h as u32);
            let mut rgba_buf = vec![0u8; (w * h * 4) as usize];
            let mut line_buf = vec![0u8; (w * 4) as usize];
            let display_handle = if w > 0 && h > 0 {
                read_framebuffer(&mut view, w, h, &mut rgba_buf, &mut line_buf);
                Some(image::Handle::from_rgba(w, h, rgba_buf.clone()))
            } else {
                None
            };
            (
                App {
                    view,
                    _input_send: input_send,
                    alive_send,
                    rgba_buf,
                    line_buf,
                    display_handle,
                    width: w,
                    height: h,
                    frame_count: 0,
                    last_stats: Instant::now(),
                },
                Task::none(),
            )
        },
        App::update,
        App::view,
    )
    .subscription(App::subscription)
    .theme(App::theme)
    .title("OpenVMM")
    .window_size((1024.0, 768.0))
    .run()
    .map_err(|e| anyhow::anyhow!("iced application error: {e}"))?;

    tracing::info!("GUI exiting");
    Ok(())
}

struct App {
    view: View,
    _input_send: mesh::Sender<input_core::InputData>,
    alive_send: mesh::Sender<()>,
    rgba_buf: Vec<u8>,
    line_buf: Vec<u8>,
    display_handle: Option<image::Handle>,
    width: u32,
    height: u32,
    frame_count: u64,
    last_stats: Instant,
}

#[derive(Debug, Clone)]
enum Message {
    Tick,
}

/// Read the framebuffer into `rgba_buf`, converting BGRX -> RGBA.
fn read_framebuffer(
    view: &mut View,
    width: u32,
    height: u32,
    rgba_buf: &mut [u8],
    line_buf: &mut [u8],
) {
    for y in 0..height as u16 {
        view.read_line(y, line_buf);
        let row_offset = y as usize * width as usize * 4;
        for x in 0..width as usize {
            let src = x * 4;
            let dst = row_offset + x * 4;
            rgba_buf[dst] = line_buf[src + 2]; // R <- B
            rgba_buf[dst + 1] = line_buf[src + 1]; // G
            rgba_buf[dst + 2] = line_buf[src]; // B <- R
            rgba_buf[dst + 3] = 0xFF; // A
        }
    }
}

impl App {
    fn update(&mut self, message: Message) -> Task<Message> {
        match message {
            Message::Tick => {
                // Exit if the VM process has closed our channel.
                if self.alive_send.is_closed() {
                    return exit();
                }

                // Check for resolution changes.
                let (w, h) = self.view.resolution();
                let (w, h) = (w as u32, h as u32);
                if w != self.width || h != self.height {
                    self.width = w;
                    self.height = h;
                    self.rgba_buf.resize((w * h * 4) as usize, 0);
                    self.line_buf.resize((w * 4) as usize, 0);
                    tracing::info!(w, h, "resolution changed");
                }

                read_framebuffer(
                    &mut self.view,
                    self.width,
                    self.height,
                    &mut self.rgba_buf,
                    &mut self.line_buf,
                );

                self.display_handle = Some(image::Handle::from_rgba(
                    self.width,
                    self.height,
                    self.rgba_buf.clone(),
                ));

                self.frame_count += 1;
                let elapsed = self.last_stats.elapsed().as_secs_f64();
                if elapsed >= 5.0 {
                    let fps = self.frame_count as f64 / elapsed;
                    tracing::info!(fps = format!("{fps:.1}"), "GUI stats");
                    self.frame_count = 0;
                    self.last_stats = Instant::now();
                }

                Task::none()
            }
        }
    }

    fn view(&self) -> Element<'_, Message> {
        let status = text(format!("{}x{}", self.width, self.height)).size(14);

        let content: Element<'_, Message> = if let Some(handle) = &self.display_handle {
            container(
                image(handle.clone())
                    .content_fit(iced::ContentFit::Contain)
                    .width(Length::Fill)
                    .height(Length::Fill),
            )
            .center(Length::Fill)
            .into()
        } else {
            container(text("Waiting for framebuffer...").size(24))
                .center(Length::Fill)
                .into()
        };

        column![
            row![text("OpenVMM").size(14), status]
                .spacing(20)
                .padding(5),
            content,
        ]
        .into()
    }

    fn subscription(&self) -> Subscription<Message> {
        iced::time::every(Duration::from_millis(16)).map(|_| Message::Tick)
    }

    fn theme(&self) -> Theme {
        Theme::Dark
    }
}
