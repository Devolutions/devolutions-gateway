pub mod health;
pub mod jet;
pub mod sessions;

pub mod utils {
    use saphir::{SyncResponse, ToBody};

    pub trait SyncResponseUtil {
        fn json_body<B: 'static + ToBody>(&mut self, body: B);
    }

    impl SyncResponseUtil for SyncResponse {
        fn json_body<B: 'static + ToBody>(&mut self, body: B) {
            self.body(body);
            self.header("Content-Type", "application/json");
        }
    }
}