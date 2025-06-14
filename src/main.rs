#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::{
    cell::RefCell,
    env, fs,
    io::{self, BufReader, Read, Write},
    thread::{self, sleep},
    time::Duration,
};

use native_windows_derive as nwd;
use native_windows_gui as nwg;

use anyhow::{Context, Error as AnyError, Result as AnyResult};
use log::{Record, debug, error, info, warn};
use nwd::NwgUi;
use nwg::NativeUi;
use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
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
        info!("Starting the request thread");
        *self.request_result.borrow_mut() = Some(thread::spawn(move || {
            let task = || -> AnyResult<Box<str>> {
                info!("Getting upload file path");
                let upload_file_path = if let Some(path) = env::args().nth(1) {
                    path
                } else {
                    warn!("Path arg not specified");
                    return Ok(Box::from("the fuck you want"));
                };

                info!("Getting file metadata");
                let upload_meta = fs::metadata(&upload_file_path)?;
                if !upload_meta.is_file() {
                    warn!("Item specified for checking is not a file");
                    return Ok(Box::from("bruh this ain a file"));
                }

                let upload_file = fs::File::open(&upload_file_path)?;
                let upload_file_hash = {
                    let mut reader = BufReader::new(&upload_file);
                    let mut hasher = Sha256::new();
                    let mut buffer = [0u8; 4096];

                    loop {
                        let n = reader.read(&mut buffer)?;
                        if n == 0 {
                            break;
                        }
                        hasher.update(&buffer[..n]);
                    }

                    hex::encode(&hasher.finalize()[..])
                };

                info!("Opening settings.ini");
                let mut settings_path = env::current_exe()?;
                settings_path.set_file_name("settings.ini");
                let conf = ini::Ini::load_from_file(settings_path)?;
                let apikey = conf
                    .section(Some("Settings"))
                    .and_then(|v| v.get("APIKEY"))
                    .context("settings.ini is invalid")?;

                let client = reqwest::blocking::Client::builder()
                    .use_native_tls()
                    .build()
                    .context("Failed to build a http client")?;

                info!("Trying to get analysis stats by the hash");
                let response = client
                    .get(format!(
                        "https://www.virustotal.com/api/v3/files/{upload_file_hash}"
                    ))
                    .header("accept", "application/json")
                    .header("x-apikey", apikey)
                    .send()?;

                if response.status().is_success() {
                    info!("Analysis found by hash");
                    let v: Value = serde_json::from_str(
                        &response.text().context("Server sent invalid data")?,
                    )?;
                    let msg = v
                        .get("data")
                        .and_then(|v| v.get("attributes"))
                        .and_then(|v| v.get("last_analysis_stats"))
                        .and_then(|v| serde_json::from_value::<AnalysisStats>(v.to_owned()).ok())
                        .context("Server sent invalid data")?
                        .score();
                    return Ok(Box::from(msg));
                } else {
                    info!("Analysis NOT found by hash");
                }

                info!("Checking file size");
                // 32MB as specifed by https://docs.virustotal.com/reference/files-scan
                let upload_url = if upload_meta.len() > 32_000_000 {
                    info!("File is larger than 32MB, requesting upload url");
                    let response = client
                        .get("https://www.virustotal.com/api/v3/files/upload_url")
                        .header("accept", "application/json")
                        .header("x-apikey", apikey)
                        .send()?;
                    let status = response.status();
                    if !status.is_success() {
                        return Err(AnyError::msg(format!(
                            "Server sent a wrong response: {status}"
                        )));
                    }
                    let v: Value = serde_json::from_str(
                        &response.text().context("Server sent invalid data")?,
                    )?;
                    v.get("data")
                        .and_then(|v| v.as_str())
                        .context("Server sent invalid data")?
                        .to_string()
                } else {
                    "https://www.virustotal.com/api/v3/files".to_string()
                };

                info!("Creating upload form");
                // TODO change .file to .part with Part::reader
                let upload_form =
                    reqwest::blocking::multipart::Form::new().file("file", &upload_file_path)?;

                info!("Uploading the file");
                let response = client
                    .post(upload_url)
                    .header("accept", "application/json")
                    .header("x-apikey", apikey)
                    .multipart(upload_form)
                    .send()?;
                let status = response.status();
                if !status.is_success() {
                    return Err(AnyError::msg(format!(
                        "Server responded with code: {status}"
                    )));
                }
                let v: Value =
                    serde_json::from_str(&response.text().context("Server sent invalid data")?)?;
                let analysis_id = v
                    .get("data")
                    .and_then(|v| v.get("id"))
                    .and_then(|v| v.as_str())
                    .context("Server sent invalid data")?;

                info!("Waiting for analysis to complete");
                let response_content = loop {
                    let response = client
                        .get(format!(
                            "https://www.virustotal.com/api/v3/analyses/{analysis_id}"
                        ))
                        .header("accept", "application/json")
                        .header("x-apikey", apikey)
                        .send()?;

                    let status = response.status();
                    if !status.is_success() {
                        return Err(AnyError::msg(format!(
                            "Server sent a wrong response: {status}"
                        )));
                    }

                    let v: Value = serde_json::from_str(&response.text()?)?;
                    let status = v
                        .get("data")
                        .and_then(|v| v.get("attributes"))
                        .and_then(|v| v.get("status"))
                        .and_then(|v| v.as_str())
                        .context("Server sent invalid data")?;
                    debug!("Analysis: {status}");
                    if status == "completed" {
                        break v;
                    }
                    sleep(Duration::from_secs(1));
                };

                info!("Reading analysis results");
                let msg = response_content
                    .get("data")
                    .and_then(|v| v.get("attributes"))
                    .and_then(|v| v.get("stats"))
                    .and_then(|v| serde_json::from_value::<AnalysisStats>(v.to_owned()).ok())
                    .context("Server sent invalid data")?
                    .score();
                Ok(Box::from(msg))
            };

            let result = task().unwrap_or_else(|e| {
                error!("Encountered an error: {e}");
                Box::from("idk")
            });
            info!("Request thread finished");
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

#[derive(Debug, Deserialize)]
struct AnalysisStats {
    malicious: u16,
    suspicious: u16,
    undetected: u16,
    harmless: u16,
    // timeout: u16,
    // #[serde(rename = "confirmed-timeout")]
    // confirmed_timeout: u16,
    // failure: u16,
    // #[serde(rename = "type-unsupported")]
    // typ_unsupported: u16,
}

impl AnalysisStats {
    fn get_bad_ratio(&self) -> f64 {
        let good = self.harmless + self.undetected;
        let bad = self.suspicious + self.malicious;
        bad as f64 / (good + bad) as f64
    }

    fn score(&self) -> &'static str {
        info!("Scoring the analysis results");
        let bad_ratio = self.get_bad_ratio();
        if bad_ratio < 0.05 {
            "looks fine bro"
        } else if bad_ratio < 0.1 {
            "kinda sus"
        } else {
            "not good"
        }
    }
}

fn start_logger() -> flexi_logger::LoggerHandle {
    use flexi_logger::{
        DeferredNow, FileSpec, LogSpecification, Logger, TS_DASHES_BLANK_COLONS_DOT_BLANK,
        colored_detailed_format,
    };

    fn release_format(
        w: &mut dyn Write,
        now: &mut DeferredNow,
        record: &Record<'_>,
    ) -> io::Result<()> {
        write!(
            w,
            "[{}] {:<5} [{}] {}",
            now.format(TS_DASHES_BLANK_COLONS_DOT_BLANK),
            record.level(),
            record.module_path().unwrap_or("<unnamed>"),
            record.args(),
        )
    }

    let logger = Logger::with(LogSpecification::debug()).use_windows_line_ending();

    let logger = if cfg!(debug_assertions) {
        logger.log_to_stdout().format(colored_detailed_format)
    } else {
        logger
            .log_to_file(
                FileSpec::default()
                    .directory(env::current_exe().unwrap().parent().unwrap())
                    .basename("ahmed")
                    .use_timestamp(false),
            )
            .format(release_format)
    };

    logger.start().unwrap()
}

fn main() {
    let logger_handle = start_logger();

    nwg::init().expect("Failed to init Native Windows GUI");
    let _app = BasicApp::build_ui(Default::default()).expect("Failed to build UI");
    nwg::dispatch_thread_events();

    logger_handle.shutdown();
}
