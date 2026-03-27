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
use iced::keyboard;
use iced::mouse;
use iced::widget::column;
use iced::widget::container;
use iced::widget::image;
use iced::widget::row;
use iced::widget::text;
use input_core::InputData;
use input_core::KeyboardData;
use input_core::MouseData;
use parking_lot::Mutex;
use std::time::Duration;
use std::time::Instant;

/// Run the GUI. This blocks until the window is closed.
pub fn run(
    framebuffer: FramebufferAccess,
    input_send: mesh::Sender<InputData>,
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
                    input_send,
                    alive_send,
                    rgba_buf,
                    line_buf,
                    display_handle,
                    width: w,
                    height: h,
                    frame_count: 0,
                    last_stats: Instant::now(),
                    mouse_position: (0.0, 0.0),
                    mouse_buttons: 0,
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
    input_send: mesh::Sender<InputData>,
    alive_send: mesh::Sender<()>,
    rgba_buf: Vec<u8>,
    line_buf: Vec<u8>,
    display_handle: Option<image::Handle>,
    width: u32,
    height: u32,
    frame_count: u64,
    last_stats: Instant,
    mouse_position: (f32, f32),
    mouse_buttons: u8,
}

#[derive(Debug, Clone)]
enum Message {
    Tick,
    KeyEvent(keyboard::Event),
    MouseEvent(mouse::Event),
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
            Message::KeyEvent(event) => {
                let (physical_key, make) = match event {
                    keyboard::Event::KeyPressed { physical_key, .. } => (physical_key, true),
                    keyboard::Event::KeyReleased { physical_key, .. } => (physical_key, false),
                    _ => return Task::none(),
                };
                if let Some(scancode) = physical_key_to_xt(physical_key) {
                    tracing::debug!(scancode, make, "keyboard input");
                    self.input_send.send(InputData::Keyboard(KeyboardData {
                        code: scancode,
                        make,
                    }));
                } else {
                    tracing::debug!(?physical_key, make, "unmapped key");
                }
                Task::none()
            }
            Message::MouseEvent(event) => {
                match event {
                    mouse::Event::CursorMoved { position } => {
                        self.mouse_position = (position.x, position.y);
                    }
                    mouse::Event::ButtonPressed(button) => {
                        self.mouse_buttons |= mouse_button_bit(button);
                    }
                    mouse::Event::ButtonReleased(button) => {
                        self.mouse_buttons &= !mouse_button_bit(button);
                    }
                    _ => return Task::none(),
                }
                self.send_mouse();
                Task::none()
            }
        }
    }

    fn send_mouse(&self) {
        // Scale window coordinates to HID absolute coordinates [0, 0x7FFF].
        // Use the framebuffer resolution as the logical coordinate space.
        let w = self.width as f32;
        let h = self.height as f32;
        if w <= 1.0 || h <= 1.0 {
            return;
        }
        let x = ((self.mouse_position.0 / w).clamp(0.0, 1.0) * 0x7FFF as f32) as u16;
        let y = ((self.mouse_position.1 / h).clamp(0.0, 1.0) * 0x7FFF as f32) as u16;
        self.input_send.send(InputData::Mouse(MouseData {
            button_mask: self.mouse_buttons,
            x,
            y,
        }));
    }

    fn view(&self) -> Element<'_, Message> {
        let status = text(format!("{}x{}", self.width, self.height)).size(14);

        let content: Element<'_, Message> = if let Some(handle) = &self.display_handle {
            container(
                image(handle.clone())
                    .filter_method(image::FilterMethod::Nearest)
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
        let tick = iced::time::every(Duration::from_millis(33)).map(|_| Message::Tick);
        let keys = keyboard::listen().map(Message::KeyEvent);
        let mouse = iced::event::listen_with(|event, _status, _id| match event {
            iced::Event::Mouse(e) => Some(Message::MouseEvent(e)),
            _ => None,
        });
        Subscription::batch([tick, keys, mouse])
    }

    fn theme(&self) -> Theme {
        Theme::Dark
    }
}

fn mouse_button_bit(button: mouse::Button) -> u8 {
    match button {
        mouse::Button::Left => 0x01,
        mouse::Button::Middle => 0x02,
        mouse::Button::Right => 0x04,
        _ => 0,
    }
}

/// Map iced physical key code to XT scancode (Set 1).
/// Extended keys use 0xE0xx encoding.
fn physical_key_to_xt(key: keyboard::key::Physical) -> Option<u16> {
    use keyboard::key::Code;
    let code = match key {
        keyboard::key::Physical::Code(c) => c,
        _ => return None,
    };
    let xt = match code {
        Code::Escape => 0x01,
        Code::Digit1 => 0x02,
        Code::Digit2 => 0x03,
        Code::Digit3 => 0x04,
        Code::Digit4 => 0x05,
        Code::Digit5 => 0x06,
        Code::Digit6 => 0x07,
        Code::Digit7 => 0x08,
        Code::Digit8 => 0x09,
        Code::Digit9 => 0x0A,
        Code::Digit0 => 0x0B,
        Code::Minus => 0x0C,
        Code::Equal => 0x0D,
        Code::Backspace => 0x0E,
        Code::Tab => 0x0F,
        Code::KeyQ => 0x10,
        Code::KeyW => 0x11,
        Code::KeyE => 0x12,
        Code::KeyR => 0x13,
        Code::KeyT => 0x14,
        Code::KeyY => 0x15,
        Code::KeyU => 0x16,
        Code::KeyI => 0x17,
        Code::KeyO => 0x18,
        Code::KeyP => 0x19,
        Code::BracketLeft => 0x1A,
        Code::BracketRight => 0x1B,
        Code::Enter => 0x1C,
        Code::ControlLeft => 0x1D,
        Code::KeyA => 0x1E,
        Code::KeyS => 0x1F,
        Code::KeyD => 0x20,
        Code::KeyF => 0x21,
        Code::KeyG => 0x22,
        Code::KeyH => 0x23,
        Code::KeyJ => 0x24,
        Code::KeyK => 0x25,
        Code::KeyL => 0x26,
        Code::Semicolon => 0x27,
        Code::Quote => 0x28,
        Code::Backquote => 0x29,
        Code::ShiftLeft => 0x2A,
        Code::Backslash => 0x2B,
        Code::KeyZ => 0x2C,
        Code::KeyX => 0x2D,
        Code::KeyC => 0x2E,
        Code::KeyV => 0x2F,
        Code::KeyB => 0x30,
        Code::KeyN => 0x31,
        Code::KeyM => 0x32,
        Code::Comma => 0x33,
        Code::Period => 0x34,
        Code::Slash => 0x35,
        Code::ShiftRight => 0x36,
        Code::NumpadMultiply => 0x37,
        Code::AltLeft => 0x38,
        Code::Space => 0x39,
        Code::CapsLock => 0x3A,
        Code::F1 => 0x3B,
        Code::F2 => 0x3C,
        Code::F3 => 0x3D,
        Code::F4 => 0x3E,
        Code::F5 => 0x3F,
        Code::F6 => 0x40,
        Code::F7 => 0x41,
        Code::F8 => 0x42,
        Code::F9 => 0x43,
        Code::F10 => 0x44,
        Code::NumLock => 0x45,
        Code::ScrollLock => 0x46,
        Code::Numpad7 => 0x47,
        Code::Numpad8 => 0x48,
        Code::Numpad9 => 0x49,
        Code::NumpadSubtract => 0x4A,
        Code::Numpad4 => 0x4B,
        Code::Numpad5 => 0x4C,
        Code::Numpad6 => 0x4D,
        Code::NumpadAdd => 0x4E,
        Code::Numpad1 => 0x4F,
        Code::Numpad2 => 0x50,
        Code::Numpad3 => 0x51,
        Code::Numpad0 => 0x52,
        Code::NumpadDecimal => 0x53,
        Code::F11 => 0x57,
        Code::F12 => 0x58,
        // Extended keys (0xE0 prefix).
        Code::NumpadEnter => 0xE01C,
        Code::ControlRight => 0xE01D,
        Code::NumpadDivide => 0xE035,
        Code::PrintScreen => 0xE037,
        Code::AltRight => 0xE038,
        Code::Home => 0xE047,
        Code::ArrowUp => 0xE048,
        Code::PageUp => 0xE049,
        Code::ArrowLeft => 0xE04B,
        Code::ArrowRight => 0xE04D,
        Code::End => 0xE04F,
        Code::ArrowDown => 0xE050,
        Code::PageDown => 0xE051,
        Code::Insert => 0xE052,
        Code::Delete => 0xE053,
        Code::SuperLeft => 0xE05B,
        Code::SuperRight => 0xE05C,
        Code::ContextMenu => 0xE05D,
        Code::Pause => 0xE11D, // special but send as extended
        _ => return None,
    };
    Some(xt)
}
