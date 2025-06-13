#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::{
    cell::RefCell,
    env,
    fs::File,
    io::Read,
    thread::{self, sleep},
    time::Duration,
};

use native_windows_derive as nwd;
use native_windows_gui as nwg;
use sha2::{Digest, Sha256};

use nwd::NwgUi;
use nwg::NativeUi;
use serde_json::Value;
use winapi::um::wingdi::{
    CombineRgn, CreatePen, CreatePolygonRgn, CreateRectRgn, CreateRoundRectRgn, CreateSolidBrush,
    DeleteObject, FillRgn, FrameRgn, PS_SOLID, RGB, RGN_OR, SelectObject, WINDING,
};

#[derive(Default, NwgUi)]
pub struct BasicApp {
    #[nwg_control( size: (400, 270), center: true, title: "Ahmed", icon: load_icon().as_ref(), flags: "WINDOW|VISIBLE" )]
    #[nwg_events( OnInit: [Self::main], OnWindowClose: [Self::exit], OnPaint: [Self::paint_bubble(SELF, EVT_DATA)] )]
    window: nwg::Window,

    #[nwg_control( bitmap: load_ahmed_img().as_ref(), size: (140, 150), position: (230, 40) )]
    image: nwg::ImageFrame,

    #[nwg_control( text: "hold up", size: (145, 150), position: (30, 35), background_color: Some([255,255,224]), font: build_font().as_ref(), flags: "MULTI_LINE|VISIBLE" )]
    text: nwg::RichLabel,

    #[nwg_control]
    #[nwg_events( OnNotice: [Self::display_result] )]
    request_notice: nwg::Notice,
    request_result: RefCell<Option<thread::JoinHandle<Box<str>>>>,

    #[nwg_control( text: "OK", size: (80, 25), position: (160, 220) )]
    #[nwg_events( OnButtonClick: [Self::exit] )]
    hello_button: nwg::Button,
}

impl BasicApp {
    fn main(&self) {
        let sender = self.request_notice.sender();
        *self.request_result.borrow_mut() = Some(thread::spawn(move || {
            let task = || {
                let file_path = match env::args().nth(1) {
                    Some(path) => path,
                    None => return Some(Box::from("the fuck you want")),
                };

                let mut file = match File::open(&file_path) {
                    Ok(f) => f,
                    Err(_) => return Some(Box::from("the fuck you want")),
                };

                let mut hasher = Sha256::new();
                let mut buffer = [0; 8192];

                loop {
                    match file.read(&mut buffer) {
                        Ok(0) => break,
                        Ok(n) => hasher.update(&buffer[..n]),
                        Err(_) => return Some(Box::from("cant read this file bro")),
                    }
                }

                let hash = format!("{:x}", hasher.finalize());

                let mut path = env::current_exe().ok()?;
                path.set_file_name("settings.ini");
                let conf = ini::Ini::load_from_file(path).ok()?;
                let apikey = conf.section(Some("Settings"))?.get("APIKEY")?;

                let client = reqwest::blocking::Client::builder()
                    .use_native_tls()
                    .build()
                    .ok()?;

                // check if file hash exists in virustotal db
                let response = client
                    .get(&format!("https://www.virustotal.com/api/v3/files/{}", hash))
                    .header("accept", "application/json")
                    .header("x-apikey", apikey)
                    .send()
                    .ok()?;

                let response_content = if response.status().is_success() {
                    serde_json::from_str(&response.text().ok()?).ok()?
                } else if response.status().as_u16() == 404 {
                    // file not found, upload it
                    let upload_form = reqwest::blocking::multipart::Form::new()
                        .file("file", &file_path)
                        .ok()?;

                    // get upload URL from virustotal
                    let response = client
                        .get("https://www.virustotal.com/api/v3/files/upload_url")
                        .header("accept", "application/json")
                        .header("x-apikey", apikey)
                        .send()
                        .ok()?;
                    let v: Value = serde_json::from_str(&response.text().ok()?).ok()?;
                    let upload_url = v.get("data")?.as_str()?;

                    // upload file to virustotal
                    let response = client
                        .post(upload_url)
                        .header("accept", "application/json")
                        .header("x-apikey", apikey)
                        .multipart(upload_form)
                        .send()
                        .ok()?;
                    let v: Value = serde_json::from_str(&response.text().ok()?).ok()?;
                    let analysis_id = v.get("data")?.get("id")?.as_str()?;

                    // wait for result
                    loop {
                        let response = client
                            .get(format!(
                                "https://www.virustotal.com/api/v3/analyses/{analysis_id}"
                            ))
                            .header("accept", "application/json")
                            .header("x-apikey", apikey)
                            .send()
                            .ok()?;

                        if !response.status().is_success() {
                            return None;
                        }

                        let v: Value = serde_json::from_str(&response.text().ok()?).ok()?;
                        let status = v.get("data")?.get("attributes")?.get("status")?.as_str()?;
                        if status == "completed" {
                            break v;
                        }
                        sleep(Duration::from_secs(1));
                    }
                } else {
                    return None;
                };

                #[derive(Default)]
                struct Agregate {
                    good: u32,
                    bad: u32,
                }

                let agregate = response_content
                    .get("data")?
                    .get("attributes")?
                    .get("last_analysis_results")?
                    .as_object()?
                    .values()
                    .map(|v| {
                        v.get("category")
                            .and_then(Value::as_str)
                            .unwrap_or("type-unsupported")
                    })
                    .fold(Agregate::default(), |mut aggr, cat| {
                        match cat {
                            "harmless" | "undetected" => aggr.good += 1,
                            "suspicious" | "malicious" => aggr.bad += 1,
                            _ => {}
                        }
                        aggr
                    });
                let bad_ratio = agregate.bad as f64 / (agregate.good + agregate.bad) as f64;

                let msg = if bad_ratio < 0.05 {
                    "looks fine bro"
                } else if bad_ratio < 0.1 {
                    "kinda sus"
                } else {
                    "not good"
                };
                Some(Box::from(msg))
            };

            let result = task().unwrap_or(Box::from("idk"));
            sender.notice();
            result
        }));
    }

    fn display_result(&self) {
        if let Some(handle) = self.request_result.borrow_mut().take() {
            let request_result = handle.join().unwrap();
            self.text.set_text(&request_result);
        }
    }

    fn paint_bubble(&self, data: &nwg::EventData) {
        use winapi::shared::windef::POINT as P;

        let paint = data.on_paint();
        let ps = paint.begin_paint();
        let hdc = ps.hdc;

        unsafe {
            // Setup pen and brush
            let pen = CreatePen(PS_SOLID as i32, 2, RGB(0, 0, 0));
            let brush = CreateSolidBrush(RGB(255, 255, 224));

            // Create regions
            let bubble = CreateRoundRectRgn(20, 25, 185, 195, 20, 20);
            let mut pts = [
                P { x: 180, y: 90 },
                P { x: 220, y: 90 },
                P { x: 180, y: 50 },
            ];
            let tail = CreatePolygonRgn(pts.as_mut_ptr(), pts.len() as i32, WINDING);

            // Combine into one region
            let combined = CreateRectRgn(0, 0, 0, 0);
            CombineRgn(combined, bubble, tail, RGN_OR);

            // Paint
            SelectObject(hdc, pen as _);
            SelectObject(hdc, brush as _);
            FillRgn(hdc, combined, brush);
            FrameRgn(hdc, combined, pen as _, 1, 1);

            // Cleanup
            DeleteObject(bubble as _);
            DeleteObject(tail as _);
            DeleteObject(combined as _);
            DeleteObject(pen as _);
            DeleteObject(brush as _);
        }

        paint.end_paint(&ps);
    }

    fn exit(&self) {
        nwg::stop_thread_dispatch();
    }
}

fn load_ahmed_img() -> Option<nwg::Bitmap> {
    nwg::Bitmap::from_bin(include_bytes!("Ahmed.png")).ok()
}

fn load_icon() -> Option<nwg::Icon> {
    nwg::Icon::from_bin(include_bytes!("Ahmed.ico")).ok()
}

fn build_font() -> Option<nwg::Font> {
    let mut font = nwg::Font::default();
    nwg::Font::builder()
        .size(24)
        .family("Segoe UI")
        .weight(500)
        .build(&mut font)
        .ok()?;

    Some(font)
}

fn main() {
    nwg::init().expect("Failed to init Native Windows GUI");
    let _app = BasicApp::build_ui(Default::default()).expect("Failed to build UI");
    nwg::dispatch_thread_events();
}
