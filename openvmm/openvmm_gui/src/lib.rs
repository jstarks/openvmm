// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! OpenVMM GUI frontend.
//!
//! Opens an egui window using wgpu (or a Windows GDI fallback when no real
//! GPU is available) to display the VM framebuffer and forward keyboard/mouse
//! input. Designed to run in a child process spawned via
//! `mesh_process::launch_host`.
//!
//! Two rendering paths are used depending on the available hardware:
//!
//! **Path 1 — wgpu + custom render pipeline (eframe)**
//!
//! Used when a real GPU is available, or on Linux (where even the software
//! Vulkan driver "lavapipe" performs well enough at ~30 FPS vsync). A custom
//! wgpu render pipeline uploads pixels via `queue.write_texture()` and draws
//! a fullscreen textured quad directly to the swapchain, then egui draws its
//! UI on top.
//!
//! **Path 2 — Windows GDI fallback (no wgpu, no WARP)**
//!
//! Used on Windows with no real GPU (only WARP software rasterizer). WARP's
//! `write_texture` path tops out at ~7 FPS for a 1080p RGBA texture due to
//! per-pixel JIT copy in `d3d10warp!Task_Copy`. Instead we use CPU
//! nearest-neighbor scaling, render egui via `egui_software_backend`'s CPU
//! triangle rasterizer, and present with a single GDI `SetDIBitsToDevice`
//! call (~25 FPS with full UI).

#![deny(unsafe_code)]

use eframe::egui;
use eframe::wgpu;
use framebuffer::FramebufferAccess;
use framebuffer::View;
use input_core::InputData;
use input_core::KeyboardData;
use input_core::MouseData;
use std::sync::Arc;
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

    #[cfg(target_os = "windows")]
    if !has_real_gpu() {
        tracing::info!("no real GPU on Windows, using GDI path");
        win32_gdi::run(view, input_send, alive_send);
        tracing::info!("GUI exiting");
        return Ok(());
    }

    tracing::info!("using wgpu backend");
    run_wgpu(view, input_send, alive_send)?;
    tracing::info!("GUI exiting");
    Ok(())
}

// ============================================================
// Shared state
// ============================================================

struct AppState {
    view: View,
    input_send: mesh::Sender<InputData>,
    alive_send: mesh::Sender<()>,
    rgba_buf: Vec<u8>,
    line_buf: Vec<u8>,
    width: u32,
    height: u32,
    frame_count: u64,
    last_stats: Instant,
    mouse_position: (f32, f32),
    mouse_buttons: u8,
}

impl AppState {
    fn new(view: View, input_send: mesh::Sender<InputData>, alive_send: mesh::Sender<()>) -> Self {
        Self {
            view,
            input_send,
            alive_send,
            rgba_buf: Vec::new(),
            line_buf: Vec::new(),
            width: 0,
            height: 0,
            frame_count: 0,
            last_stats: Instant::now(),
            mouse_position: (0.0, 0.0),
            mouse_buttons: 0,
        }
    }

    /// Update the framebuffer, returning true if the resolution changed.
    fn update_framebuffer(&mut self) -> bool {
        let (w, h) = self.view.resolution();
        let (w, h) = (w as u32, h as u32);
        let changed = w != self.width || h != self.height;
        if changed {
            self.width = w;
            self.height = h;
            self.rgba_buf.resize((w * h * 4) as usize, 0);
            self.line_buf.resize((w * 4) as usize, 0);
            tracing::info!(w, h, "resolution changed");
        }
        if w > 0 && h > 0 {
            read_framebuffer(&mut self.view, w, h, &mut self.rgba_buf, &mut self.line_buf);
        }
        changed
    }

    fn tick_fps(&mut self) {
        self.frame_count += 1;
        let elapsed = self.last_stats.elapsed().as_secs_f64();
        if elapsed >= 5.0 {
            let fps = self.frame_count as f64 / elapsed;
            tracing::info!(fps = format!("{fps:.1}"), "GUI stats");
            self.frame_count = 0;
            self.last_stats = Instant::now();
        }
    }

    fn process_input(&mut self, ctx: &egui::Context) {
        ctx.input(|input| {
            for event in &input.events {
                match event {
                    egui::Event::Key {
                        physical_key,
                        pressed,
                        repeat,
                        ..
                    } => {
                        if *repeat {
                            continue;
                        }
                        if let Some(key) = physical_key {
                            if let Some(scancode) = egui_key_to_xt(*key) {
                                tracing::debug!(scancode, make = *pressed, "keyboard input");
                                self.input_send.send(InputData::Keyboard(KeyboardData {
                                    code: scancode,
                                    make: *pressed,
                                }));
                            }
                        }
                    }
                    egui::Event::PointerMoved(pos) => {
                        self.mouse_position = (pos.x, pos.y);
                        self.send_mouse();
                    }
                    egui::Event::PointerButton {
                        button, pressed, ..
                    } => {
                        let bit = mouse_button_bit(*button);
                        if *pressed {
                            self.mouse_buttons |= bit;
                        } else {
                            self.mouse_buttons &= !bit;
                        }
                        self.send_mouse();
                    }
                    _ => {}
                }
            }
        });
    }

    fn send_mouse(&self) {
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

    fn show_menu_bar(&self, ctx: &egui::Context) {
        egui::TopBottomPanel::top("menu_bar").show(ctx, |ui| {
            egui::MenuBar::new().ui(ui, |ui| {
                ui.label("OpenVMM");
                ui.separator();
                ui.label(format!("{}x{}", self.width, self.height));
            });
        });
    }
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

// ============================================================
// Path 1: wgpu + custom render pipeline via CallbackTrait
// ============================================================

use eframe::egui_wgpu;

/// GPU-side resources for the pixel surface.
struct SurfaceGpu {
    texture: wgpu::Texture,
    bind_group: wgpu::BindGroup,
    pipeline: wgpu::RenderPipeline,
    width: u32,
    height: u32,
}

/// Per-frame callback that uploads pixel data and draws the fullscreen quad.
struct SurfaceCallback {
    pixels: Arc<[u8]>,
    width: u32,
    height: u32,
}

impl egui_wgpu::CallbackTrait for SurfaceCallback {
    fn prepare(
        &self,
        _device: &wgpu::Device,
        queue: &wgpu::Queue,
        _screen_descriptor: &egui_wgpu::ScreenDescriptor,
        _encoder: &mut wgpu::CommandEncoder,
        callback_resources: &mut egui_wgpu::CallbackResources,
    ) -> Vec<wgpu::CommandBuffer> {
        let gpu: &SurfaceGpu = callback_resources.get().unwrap();
        if self.width == gpu.width && self.height == gpu.height && self.width > 0 {
            queue.write_texture(
                wgpu::TexelCopyTextureInfo {
                    texture: &gpu.texture,
                    mip_level: 0,
                    origin: wgpu::Origin3d::ZERO,
                    aspect: wgpu::TextureAspect::All,
                },
                &self.pixels,
                wgpu::TexelCopyBufferLayout {
                    offset: 0,
                    bytes_per_row: Some(self.width * 4),
                    rows_per_image: Some(self.height),
                },
                wgpu::Extent3d {
                    width: self.width,
                    height: self.height,
                    depth_or_array_layers: 1,
                },
            );
        }
        Vec::new()
    }

    fn paint(
        &self,
        _info: egui::PaintCallbackInfo,
        render_pass: &mut wgpu::RenderPass<'static>,
        callback_resources: &egui_wgpu::CallbackResources,
    ) {
        let gpu: &SurfaceGpu = callback_resources.get().unwrap();
        if gpu.width > 0 {
            render_pass.set_pipeline(&gpu.pipeline);
            render_pass.set_bind_group(0, &gpu.bind_group, &[]);
            render_pass.draw(0..6, 0..1);
        }
    }
}

fn create_surface_gpu(
    device: &wgpu::Device,
    target_format: wgpu::TextureFormat,
    width: u32,
    height: u32,
) -> SurfaceGpu {
    let w = width.max(1);
    let h = height.max(1);

    let texture = device.create_texture(&wgpu::TextureDescriptor {
        label: Some("surface_tex"),
        size: wgpu::Extent3d {
            width: w,
            height: h,
            depth_or_array_layers: 1,
        },
        mip_level_count: 1,
        sample_count: 1,
        dimension: wgpu::TextureDimension::D2,
        format: wgpu::TextureFormat::Rgba8UnormSrgb,
        usage: wgpu::TextureUsages::TEXTURE_BINDING | wgpu::TextureUsages::COPY_DST,
        view_formats: &[],
    });

    let view = texture.create_view(&Default::default());
    let sampler = device.create_sampler(&wgpu::SamplerDescriptor {
        mag_filter: wgpu::FilterMode::Linear,
        min_filter: wgpu::FilterMode::Linear,
        ..Default::default()
    });

    let shader = device.create_shader_module(wgpu::ShaderModuleDescriptor {
        label: Some("surface_shader"),
        source: wgpu::ShaderSource::Wgsl(include_str!("surface.wgsl").into()),
    });

    let bgl = device.create_bind_group_layout(&wgpu::BindGroupLayoutDescriptor {
        label: None,
        entries: &[
            wgpu::BindGroupLayoutEntry {
                binding: 0,
                visibility: wgpu::ShaderStages::FRAGMENT,
                ty: wgpu::BindingType::Texture {
                    sample_type: wgpu::TextureSampleType::Float { filterable: true },
                    view_dimension: wgpu::TextureViewDimension::D2,
                    multisampled: false,
                },
                count: None,
            },
            wgpu::BindGroupLayoutEntry {
                binding: 1,
                visibility: wgpu::ShaderStages::FRAGMENT,
                ty: wgpu::BindingType::Sampler(wgpu::SamplerBindingType::Filtering),
                count: None,
            },
        ],
    });

    let bind_group = device.create_bind_group(&wgpu::BindGroupDescriptor {
        label: None,
        layout: &bgl,
        entries: &[
            wgpu::BindGroupEntry {
                binding: 0,
                resource: wgpu::BindingResource::TextureView(&view),
            },
            wgpu::BindGroupEntry {
                binding: 1,
                resource: wgpu::BindingResource::Sampler(&sampler),
            },
        ],
    });

    let pipeline_layout = device.create_pipeline_layout(&wgpu::PipelineLayoutDescriptor {
        label: None,
        bind_group_layouts: &[&bgl],
        push_constant_ranges: &[],
    });

    let pipeline = device.create_render_pipeline(&wgpu::RenderPipelineDescriptor {
        label: Some("surface_pipeline"),
        layout: Some(&pipeline_layout),
        vertex: wgpu::VertexState {
            module: &shader,
            entry_point: Some("vs_main"),
            buffers: &[],
            compilation_options: Default::default(),
        },
        fragment: Some(wgpu::FragmentState {
            module: &shader,
            entry_point: Some("fs_main"),
            targets: &[Some(wgpu::ColorTargetState {
                format: target_format,
                blend: None,
                write_mask: wgpu::ColorWrites::ALL,
            })],
            compilation_options: Default::default(),
        }),
        primitive: wgpu::PrimitiveState::default(),
        depth_stencil: None,
        multisample: wgpu::MultisampleState::default(),
        multiview: None,
        cache: None,
    });

    SurfaceGpu {
        texture,
        bind_group,
        pipeline,
        width,
        height,
    }
}

struct WgpuApp {
    state: AppState,
    target_format: wgpu::TextureFormat,
}

impl WgpuApp {
    fn new(
        cc: &eframe::CreationContext<'_>,
        view: View,
        input_send: mesh::Sender<InputData>,
        alive_send: mesh::Sender<()>,
    ) -> Self {
        let rs = cc
            .wgpu_render_state
            .as_ref()
            .expect("wgpu backend required");

        let mut state = AppState::new(view, input_send, alive_send);
        state.update_framebuffer();

        let gpu = create_surface_gpu(&rs.device, rs.target_format, state.width, state.height);
        rs.renderer.write().callback_resources.insert(gpu);

        Self {
            state,
            target_format: rs.target_format,
        }
    }
}

impl eframe::App for WgpuApp {
    fn update(&mut self, ctx: &egui::Context, frame: &mut eframe::Frame) {
        // Exit if the VM process has closed our channel.
        if self.state.alive_send.is_closed() {
            ctx.send_viewport_cmd(egui::ViewportCommand::Close);
            return;
        }

        self.state.tick_fps();
        self.state.process_input(ctx);

        let resolution_changed = self.state.update_framebuffer();
        if resolution_changed {
            // Recreate GPU resources for the new resolution.
            if let Some(rs) = frame.wgpu_render_state() {
                let gpu = create_surface_gpu(
                    &rs.device,
                    self.target_format,
                    self.state.width,
                    self.state.height,
                );
                rs.renderer.write().callback_resources.insert(gpu);
            }
        }

        let pixels: Arc<[u8]> = Arc::from(&self.state.rgba_buf[..]);
        let width = self.state.width;
        let height = self.state.height;

        self.state.show_menu_bar(ctx);

        egui::CentralPanel::default().show(ctx, |ui| {
            let size = ui.available_size();
            let (rect, _) = ui.allocate_exact_size(size, egui::Sense::hover());

            if width > 0 && height > 0 {
                ui.painter().add(egui_wgpu::Callback::new_paint_callback(
                    rect,
                    SurfaceCallback {
                        pixels,
                        width,
                        height,
                    },
                ));
            } else {
                ui.centered_and_justified(|ui| {
                    ui.label("Waiting for framebuffer...");
                });
            }
        });

        ctx.request_repaint();
    }
}

fn run_wgpu(
    view: View,
    input_send: mesh::Sender<InputData>,
    alive_send: mesh::Sender<()>,
) -> anyhow::Result<()> {
    let options = eframe::NativeOptions {
        wgpu_options: egui_wgpu::WgpuConfiguration {
            present_mode: wgpu::PresentMode::AutoVsync,
            ..Default::default()
        },
        ..Default::default()
    };
    eframe::run_native(
        "OpenVMM",
        options,
        Box::new(|cc| Ok(Box::new(WgpuApp::new(cc, view, input_send, alive_send)))),
    )
    .map_err(|e| anyhow::anyhow!("eframe error: {e}"))?;
    Ok(())
}

// ============================================================
// Path 2: Windows no-GPU — winit + GDI
// ============================================================

#[cfg(target_os = "windows")]
#[allow(unsafe_code)]
mod win32_gdi {
    use super::*;
    use egui_software_backend::{BufferMutRef, ColorFieldOrder, EguiSoftwareRender};
    use raw_window_handle::{HasWindowHandle, RawWindowHandle};
    use std::ffi::c_void;
    use windows::Win32::Foundation::*;
    use windows::Win32::Graphics::Gdi::*;

    /// Blit BGRA pixels to a window DC.
    fn blit_pixels(hwnd: isize, pixels: &[u8], w: i32, h: i32) {
        let bmi = BITMAPINFO {
            bmiHeader: BITMAPINFOHEADER {
                biSize: size_of::<BITMAPINFOHEADER>() as u32,
                biWidth: w,
                biHeight: -h,
                biPlanes: 1,
                biBitCount: 32,
                biCompression: BI_RGB.0 as u32,
                ..Default::default()
            },
            ..Default::default()
        };

        let hwnd = HWND(hwnd as *mut c_void);
        // SAFETY: GDI calls with valid HWND and pixel buffer. The HWND is
        // obtained from winit's window handle and the buffer is sized correctly.
        unsafe {
            let hdc = GetDC(Some(hwnd));
            SetDIBitsToDevice(
                hdc,
                0,
                0,
                w as u32,
                h as u32,
                0,
                0,
                0,
                h as u32,
                pixels.as_ptr() as *const c_void,
                &bmi,
                DIB_RGB_COLORS,
            );
            ReleaseDC(Some(hwnd), hdc);
        }
    }

    pub fn run(view: View, input_send: mesh::Sender<InputData>, alive_send: mesh::Sender<()>) {
        use winit::application::ApplicationHandler;
        use winit::event::WindowEvent;
        use winit::event_loop::{ActiveEventLoop, EventLoop};
        use winit::window::{Window, WindowId};

        struct GdiApp {
            window: Option<Arc<Window>>,
            renderer: EguiSoftwareRender,
            egui_ctx: egui::Context,
            egui_winit: Option<egui_winit::State>,
            state: AppState,
            overlay_buf: Vec<[u8; 4]>,
        }

        impl ApplicationHandler for GdiApp {
            fn resumed(&mut self, event_loop: &ActiveEventLoop) {
                if self.window.is_none() {
                    let attrs = Window::default_attributes()
                        .with_title("OpenVMM")
                        .with_inner_size(winit::dpi::LogicalSize::new(1024.0, 768.0));
                    let window = Arc::new(event_loop.create_window(attrs).unwrap());
                    self.egui_winit = Some(egui_winit::State::new(
                        self.egui_ctx.clone(),
                        egui::ViewportId::ROOT,
                        &window,
                        None,
                        None,
                        None,
                    ));
                    self.window = Some(window);
                }
            }

            fn about_to_wait(&mut self, _event_loop: &ActiveEventLoop) {
                if let Some(window) = &self.window {
                    window.request_redraw();
                }
            }

            fn window_event(
                &mut self,
                event_loop: &ActiveEventLoop,
                _window_id: WindowId,
                event: WindowEvent,
            ) {
                let Some(window) = &self.window else { return };

                if let Some(ew) = &mut self.egui_winit {
                    let _ = ew.on_window_event(window, &event);
                }

                match event {
                    WindowEvent::CloseRequested => event_loop.exit(),
                    WindowEvent::RedrawRequested => {
                        // Exit if the VM process has closed our channel.
                        if self.state.alive_send.is_closed() {
                            event_loop.exit();
                            return;
                        }

                        let phys = window.inner_size();
                        let w = phys.width as i32;
                        let h = phys.height as i32;
                        if w <= 0 || h <= 0 {
                            return;
                        }

                        let hwnd = match window.window_handle() {
                            Ok(wh) => match wh.as_raw() {
                                RawWindowHandle::Win32(h) => h.hwnd.get() as isize,
                                _ => return,
                            },
                            _ => return,
                        };

                        self.state.tick_fps();
                        self.state.update_framebuffer();

                        // Scale framebuffer into full-window overlay buffer (BGRA).
                        let ow = w as usize;
                        let oh = h as usize;
                        let sw = self.state.width as usize;
                        let sh = self.state.height as usize;
                        self.overlay_buf.resize(ow * oh, [0, 0, 0, 0xFF]);

                        if sw > 0 && sh > 0 {
                            for dy in 0..oh {
                                let sy = dy * sh / oh;
                                for dx in 0..ow {
                                    let sx = dx * sw / ow;
                                    let si = (sy * sw + sx) * 4;
                                    // Convert RGBA -> BGRA for GDI.
                                    self.overlay_buf[dy * ow + dx] = [
                                        self.state.rgba_buf[si + 2], // B
                                        self.state.rgba_buf[si + 1], // G
                                        self.state.rgba_buf[si],     // R
                                        0xFF,
                                    ];
                                }
                            }
                        }

                        // Render egui overlay on top.
                        let raw_input = self.egui_winit.as_mut().unwrap().take_egui_input(window);

                        // Process input events for the VM.
                        let full_output = self.egui_ctx.run(raw_input, |ctx| {
                            self.state.process_input(ctx);
                            self.state.show_menu_bar(ctx);
                        });

                        self.egui_winit
                            .as_mut()
                            .unwrap()
                            .handle_platform_output(window, full_output.platform_output);

                        let prims = self
                            .egui_ctx
                            .tessellate(full_output.shapes, full_output.pixels_per_point);

                        let mut buf_ref = BufferMutRef::new(&mut self.overlay_buf, ow, oh);
                        self.renderer.render(
                            &mut buf_ref,
                            &prims,
                            &full_output.textures_delta,
                            full_output.pixels_per_point,
                        );

                        let final_bytes: &[u8] = bytemuck::cast_slice(&self.overlay_buf);
                        blit_pixels(hwnd, final_bytes, ow as i32, oh as i32);

                        window.request_redraw();
                    }
                    _ => {}
                }
            }
        }

        let event_loop = EventLoop::new().unwrap();
        let mut app = GdiApp {
            window: None,
            renderer: EguiSoftwareRender::new(ColorFieldOrder::Bgra).with_caching(false),
            egui_ctx: egui::Context::default(),
            egui_winit: None,
            state: AppState::new(view, input_send, alive_send),
            overlay_buf: Vec::new(),
        };
        event_loop.run_app(&mut app).unwrap();
    }
}

// ============================================================
// GPU detection
// ============================================================

#[cfg(target_os = "windows")]
fn has_real_gpu() -> bool {
    let instance = wgpu::Instance::new(&wgpu::InstanceDescriptor::default());
    let adapters: Vec<_> = instance.enumerate_adapters(wgpu::Backends::all());
    for a in &adapters {
        let info = a.get_info();
        tracing::info!(name = %info.name, device_type = ?info.device_type, "GPU adapter");
    }
    adapters
        .iter()
        .any(|a| a.get_info().device_type != wgpu::DeviceType::Cpu)
}

// ============================================================
// Input mapping
// ============================================================

fn mouse_button_bit(button: egui::PointerButton) -> u8 {
    match button {
        egui::PointerButton::Primary => 0x01,
        egui::PointerButton::Middle => 0x02,
        egui::PointerButton::Secondary => 0x04,
        _ => 0,
    }
}

/// Map egui physical key to XT scancode (Set 1).
/// Extended keys use 0xE0xx encoding.
///
/// Note: egui's `Key` enum does not distinguish left/right variants for
/// modifier keys (Shift, Ctrl, Alt, Super). These are mapped to the left
/// scancode. For full left/right distinction, raw winit key events would
/// be needed.
fn egui_key_to_xt(key: egui::Key) -> Option<u16> {
    let xt = match key {
        egui::Key::Escape => 0x01,
        egui::Key::Num1 => 0x02,
        egui::Key::Num2 => 0x03,
        egui::Key::Num3 => 0x04,
        egui::Key::Num4 => 0x05,
        egui::Key::Num5 => 0x06,
        egui::Key::Num6 => 0x07,
        egui::Key::Num7 => 0x08,
        egui::Key::Num8 => 0x09,
        egui::Key::Num9 => 0x0A,
        egui::Key::Num0 => 0x0B,
        egui::Key::Minus => 0x0C,
        egui::Key::Plus => 0x0D,
        egui::Key::Backspace => 0x0E,
        egui::Key::Tab => 0x0F,
        egui::Key::Q => 0x10,
        egui::Key::W => 0x11,
        egui::Key::E => 0x12,
        egui::Key::R => 0x13,
        egui::Key::T => 0x14,
        egui::Key::Y => 0x15,
        egui::Key::U => 0x16,
        egui::Key::I => 0x17,
        egui::Key::O => 0x18,
        egui::Key::P => 0x19,
        egui::Key::OpenBracket => 0x1A,
        egui::Key::CloseBracket => 0x1B,
        egui::Key::Enter => 0x1C,
        egui::Key::A => 0x1E,
        egui::Key::S => 0x1F,
        egui::Key::D => 0x20,
        egui::Key::F => 0x21,
        egui::Key::G => 0x22,
        egui::Key::H => 0x23,
        egui::Key::J => 0x24,
        egui::Key::K => 0x25,
        egui::Key::L => 0x26,
        egui::Key::Semicolon => 0x27,
        egui::Key::Quote => 0x28,
        egui::Key::Backtick => 0x29,
        egui::Key::Backslash => 0x2B,
        egui::Key::Z => 0x2C,
        egui::Key::X => 0x2D,
        egui::Key::C => 0x2E,
        egui::Key::V => 0x2F,
        egui::Key::B => 0x30,
        egui::Key::N => 0x31,
        egui::Key::M => 0x32,
        egui::Key::Comma => 0x33,
        egui::Key::Period => 0x34,
        egui::Key::Slash => 0x35,
        egui::Key::Space => 0x39,
        egui::Key::F1 => 0x3B,
        egui::Key::F2 => 0x3C,
        egui::Key::F3 => 0x3D,
        egui::Key::F4 => 0x3E,
        egui::Key::F5 => 0x3F,
        egui::Key::F6 => 0x40,
        egui::Key::F7 => 0x41,
        egui::Key::F8 => 0x42,
        egui::Key::F9 => 0x43,
        egui::Key::F10 => 0x44,
        egui::Key::F11 => 0x57,
        egui::Key::F12 => 0x58,
        // Extended keys (0xE0 prefix).
        egui::Key::Home => 0xE047,
        egui::Key::ArrowUp => 0xE048,
        egui::Key::PageUp => 0xE049,
        egui::Key::ArrowLeft => 0xE04B,
        egui::Key::ArrowRight => 0xE04D,
        egui::Key::End => 0xE04F,
        egui::Key::ArrowDown => 0xE050,
        egui::Key::PageDown => 0xE051,
        egui::Key::Insert => 0xE052,
        egui::Key::Delete => 0xE053,
        _ => return None,
    };
    Some(xt)
}
