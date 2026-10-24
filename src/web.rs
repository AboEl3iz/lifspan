use std::net::TcpListener;
use std::io::{Read, Write};
use std::sync::{Arc, Mutex};
use std::thread;
use crate::tracker::SkbTracker;

pub fn start_web_server(tracker: Arc<Mutex<SkbTracker>>, port: u16) {
    let addr = format!("0.0.0.0:{}", port);
    let listener = match TcpListener::bind(&addr) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("Failed to bind web server to {}: {}", addr, e);
            return;
        }
    };

    println!("[INFO] [Web Visualization Engine] Running live lifespan graph server at: http://localhost:{}", port);

    for stream in listener.incoming() {
        if let Ok(mut stream) = stream {
            let tracker = Arc::clone(&tracker);
            thread::spawn(move || {
                let mut buffer = [0; 2048];
                if stream.read(&mut buffer).is_err() {
                    return;
                }

                let req_str = String::from_utf8_lossy(&buffer);
                let first_line = req_str.lines().next().unwrap_or("");
                let mut parts = first_line.split_whitespace();
                let method = parts.next().unwrap_or("");
                let path = parts.next().unwrap_or("");

                if method == "GET" {
                    if path == "/api/graph" {
                        let snapshot = tracker.lock().unwrap().get_snapshot();
                        let json = serde_json::to_string(&snapshot).unwrap_or_default();
                        send_response(&mut stream, "200 OK", "application/json", &json);
                    } else if path == "/api/events" {
                        let events = tracker.lock().unwrap().get_recent_events();
                        let json = serde_json::to_string(&events).unwrap_or_default();
                        send_response(&mut stream, "200 OK", "application/json", &json);
                    } else {
                        let html = include_str!("index.html");
                        send_response(&mut stream, "200 OK", "text/html", html);
                    }
                }
            });
        }
    }
}

fn send_response(stream: &mut std::net::TcpStream, status: &str, content_type: &str, body: &str) {
    let response = format!(
        "HTTP/1.1 {}\r\nContent-Type: {}; charset=UTF-8\r\nContent-Length: {}\r\nAccess-Control-Allow-Origin: *\r\n\r\n{}",
        status,
        content_type,
        body.len(),
        body
    );
    let _ = stream.write_all(response.as_bytes());
}
