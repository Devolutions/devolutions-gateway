pub trait Reopenable: std::io::Seek {
    fn reopen(&mut self) -> std::io::Result<()>;
}
