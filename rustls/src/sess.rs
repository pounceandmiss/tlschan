//! A TLS session driven over the channel layer's tlsb_io callbacks.

use std::ffi::{c_long, c_void, CString};
use std::io::{self, ErrorKind, Read, Write};
use std::sync::Arc;

use rustls::server::Acceptor;
use rustls::{Connection, Error, HandshakeKind, ProtocolVersion};

use crate::conf::{iana, Conf};
use crate::errors::describe;
use crate::verify::{Callback, VerifyFn};

pub const OK: i32 = 0;
pub const ERROR: i32 = -1;
pub const WANT_READ: i32 = -2;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct Io {
    ud: *mut c_void,
    recv: Option<unsafe extern "C" fn(*mut c_void, *mut u8, usize) -> c_long>,
    send: Option<unsafe extern "C" fn(*mut c_void, *const u8, usize)>,
    verify: Option<VerifyFn>,
}

/// recv/send as a byte stream for rustls; recv returning 0 means "no data yet".
impl Read for Io {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let recv = self.recv.ok_or(ErrorKind::Unsupported)?;
        // SAFETY: the channel layer's callback, given a buffer we own.
        match unsafe { recv(self.ud, buf.as_mut_ptr(), buf.len()) } {
            n if n > 0 => Ok((n as usize).min(buf.len())),
            0 => Err(ErrorKind::WouldBlock.into()),
            _ => Ok(0),
        }
    }
}

impl Write for Io {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let send = self.send.ok_or(ErrorKind::Unsupported)?;
        // SAFETY: the channel layer's callback, given a buffer we own.
        unsafe { send(self.ud, buf.as_ptr(), buf.len()) };
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Output of tlsb_info_get, borrowed from the session.
pub struct Info<'a> {
    pub protocol: &'static std::ffi::CStr,
    pub cipher: &'a CString,
    pub bits: i32,
    pub alpn: Option<&'a [u8]>,
    pub servername: Option<&'a CString>,
    pub resumed: bool,
}

pub struct Sess {
    /// None while a server waits for the ClientHello.
    conn: Option<Connection>,
    /// A server's until the ClientHello is in.
    acceptor: Option<Acceptor>,
    io: Io,
    cb: Option<Callback>,
    conf: Arc<Conf>,
    /// The servername a client sent as SNI (IP addresses are not sent).
    sni: Option<CString>,
    /// The first error; it makes every later call fail.
    err: Option<CString>,
    /// recv reported EOF.
    eof: bool,
    /// read has returned 0 to the caller.
    eof_delivered: bool,
    /// Storage for the strings tlsb_info_get hands out.
    info_cipher: CString,
    info_servername: Option<CString>,
}

impl Sess {
    pub fn new(conf: Arc<Conf>, servername: Option<&str>, io: &Io) -> Result<Sess, String> {
        if io.recv.is_none() || io.send.is_none() {
            return Err("recv and send callbacks are required".into());
        }
        let cb = io.verify.map(|f| Callback { f, ud: io.ud });
        let (conn, acceptor) = if conf.is_server() {
            (None, Some(Acceptor::default()))
        } else {
            let mut c = Connection::Client(conf.client(servername, cb)?);
            c.set_buffer_limit(None);
            (Some(c), None)
        };
        let sni = servername
            .filter(|n| n.parse::<std::net::IpAddr>().is_err())
            .and_then(|n| CString::new(n).ok());
        Ok(Sess {
            conn,
            acceptor,
            io: *io,
            cb,
            conf,
            sni,
            err: None,
            eof: false,
            eof_delivered: false,
            info_cipher: CString::default(),
            info_servername: None,
        })
    }

    pub fn errmsg(&self) -> Option<&CString> {
        self.err.as_ref()
    }

    fn fail(&mut self, msg: String) -> i32 {
        self.flush();
        self.err
            .get_or_insert_with(|| CString::new(msg).unwrap_or_default());
        ERROR
    }

    /// Verification failures first, then EOF, then alerts, then the rest.
    fn fail_tls(&mut self, prefix: &str, e: &Error) -> i32 {
        let msg = match e {
            Error::InvalidCertificate(_) | Error::NoCertificatesPresented => describe(e),
            _ if self.eof => self.closed(),
            Error::AlertReceived(_) => describe(e),
            e => format!("{prefix}{}", describe(e)),
        };
        self.fail(msg)
    }

    fn closed(&self) -> String {
        if self.conn.as_ref().is_some_and(|c| !c.is_handshaking()) {
            "connection closed".into()
        } else {
            "connection closed during handshake".into()
        }
    }

    fn flush(&mut self) {
        let Some(conn) = self.conn.as_mut() else {
            return;
        };
        while conn.wants_write() {
            if conn.write_tls(&mut self.io).is_err() {
                break;
            }
        }
    }

    /// One recv + process step; `prefix` starts any error message.
    fn pump(&mut self, prefix: &str) -> Result<(), i32> {
        let r = match (self.conn.as_mut(), self.acceptor.as_mut()) {
            (Some(c), _) => c.read_tls(&mut self.io),
            (None, Some(a)) => a.read_tls(&mut self.io),
            (None, None) => return Err(ERROR),
        };
        match r {
            Ok(0) => self.eof = true,
            Ok(_) if self.conn.is_none() => self.accept()?,
            Ok(_) => self.process(prefix)?,
            Err(e) if e.kind() == ErrorKind::WouldBlock => return Err(WANT_READ),
            Err(e) => return Err(self.fail(format!("{prefix}{e}"))),
        }
        Ok(())
    }

    fn process(&mut self, prefix: &str) -> Result<(), i32> {
        let Some(conn) = self.conn.as_mut() else {
            return Ok(());
        };
        let r = conn.process_new_packets();
        self.flush();
        r.map(drop).map_err(|e| self.fail_tls(prefix, &e))
    }

    /// Server: picks the config once the ClientHello is in.
    fn accept(&mut self) -> Result<(), i32> {
        let Some(a) = self.acceptor.as_mut() else {
            return Ok(());
        };
        let r = match a.accept() {
            Ok(None) => return Ok(()),
            Ok(Some(acc)) => {
                let offered = acc.client_hello().alpn().map(|i| i.collect());
                match self.conf.server(offered, self.cb) {
                    Ok(cfg) => acc.into_connection(cfg),
                    Err(e) => return Err(self.fail(e)),
                }
            }
            Err(e) => Err(e),
        };
        self.acceptor = None;
        match r {
            Ok(mut c) => {
                c.set_buffer_limit(None);
                self.conn = Some(Connection::Server(c));
                self.process("")
            }
            Err((e, mut alert)) => {
                let _ = alert.write_all(&mut self.io);
                Err(self.fail_tls("", &e))
            }
        }
    }

    pub fn handshake(&mut self) -> i32 {
        loop {
            if self.err.is_some() {
                return ERROR;
            }
            self.flush();
            if self.conn.as_ref().is_some_and(|c| !c.is_handshaking()) {
                return OK;
            }
            if self.eof {
                return self.fail(self.closed());
            }
            if let Err(c) = self.pump("") {
                return c;
            }
        }
    }

    pub fn read(&mut self, buf: &mut [u8]) -> c_long {
        match self.handshake() {
            OK if buf.is_empty() => return 0,
            OK => {}
            c => return c.into(),
        }
        // Records pending() already took in may hold an error.
        if let Err(c) = self.process("read failed: ") {
            return c.into();
        }
        loop {
            let Some(conn) = self.conn.as_mut() else {
                return ERROR.into();
            };
            match conn.reader().read(buf) {
                Ok(n) if n > 0 => return n as c_long,
                Ok(_) => break, // close_notify
                Err(e) if e.kind() == ErrorKind::WouldBlock => {}
                Err(e) if e.kind() == ErrorKind::UnexpectedEof => break,
                Err(e) => return self.fail(format!("read failed: {e}")).into(),
            }
            if self.eof {
                break;
            }
            if let Err(c) = self.pump("read failed: ") {
                return c.into();
            }
        }
        self.eof_delivered = true;
        0
    }

    pub fn write(&mut self, buf: &[u8]) -> c_long {
        if self.err.is_some() {
            return ERROR.into();
        }
        let Some(conn) = self.conn.as_mut().filter(|c| !c.is_handshaking()) else {
            return self.fail("handshake not complete".into()).into();
        };
        if let Err(e) = conn.writer().write_all(buf) {
            return self.fail(format!("write failed: {e}")).into();
        }
        self.flush();
        buf.len() as c_long
    }

    pub fn pending(&mut self) -> bool {
        if self.err.is_some() || self.eof_delivered {
            return false;
        }
        let Some(conn) = self.conn.as_mut().filter(|c| !c.is_handshaking()) else {
            return false;
        };
        match conn.process_new_packets() {
            Ok(st) => st.plaintext_bytes_to_read() > 0 || st.peer_has_closed() || self.eof,
            Err(_) => true,
        }
    }

    pub fn close_notify(&mut self) {
        if let Some(c) = self.conn.as_mut() {
            c.send_close_notify();
        }
        self.flush();
    }

    pub fn info(&mut self) -> Option<Info<'_>> {
        let conn = self.conn.as_ref().filter(|c| !c.is_handshaking())?;
        let suite = conn.negotiated_cipher_suite()?;
        let protocol = match conn.protocol_version()? {
            ProtocolVersion::TLSv1_3 => c"TLS1.3",
            ProtocolVersion::TLSv1_2 => c"TLS1.2",
            _ => c"unknown",
        };
        let name = iana(suite.suite());
        // Every suite is AES-128, AES-256 or ChaCha20 (256).
        let bits = if name.contains("AES_128") { 128 } else { 256 };
        let servername = match conn {
            Connection::Client(_) => self.sni.clone(),
            Connection::Server(s) => s.server_name().and_then(|n| CString::new(n).ok()),
        };
        let resumed = conn.handshake_kind() == Some(HandshakeKind::Resumed);
        self.info_cipher = CString::new(name).unwrap_or_default();
        self.info_servername = servername;
        Some(Info {
            protocol,
            cipher: &self.info_cipher,
            bits,
            alpn: self.conn.as_ref()?.alpn_protocol(),
            servername: self.info_servername.as_ref(),
            resumed,
        })
    }

    pub fn peer_cert(&self, depth: usize) -> Option<&[u8]> {
        self.conn
            .as_ref()?
            .peer_certificates()?
            .get(depth)
            .map(|c| c.as_ref())
    }

    pub fn local_cert(&self) -> Option<&[u8]> {
        self.conf.local.as_ref().map(|c| c.as_ref())
    }

    pub fn export(&self, label: &[u8], ctx: Option<&[u8]>, out: &mut [u8]) -> bool {
        self.conn
            .as_ref()
            .is_some_and(|c| c.export_keying_material(out, label, ctx).is_ok())
    }
}
