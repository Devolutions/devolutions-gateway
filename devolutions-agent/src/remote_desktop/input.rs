use ironrdp::server::{KeyboardEvent, MouseEvent, RdpServerInputHandler};

#[derive(Clone, Debug)]
pub struct InputHandler;

impl InputHandler {
    pub fn new() -> Self {
        Self
    }
}

impl RdpServerInputHandler for InputHandler {
    fn keyboard(&mut self, event: KeyboardEvent) {
        trace!(?event, "keyboard");
    }

    fn mouse(&mut self, event: MouseEvent) {
        trace!(?event, "mouse");
    }
}
