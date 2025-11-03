use std::str::from_utf8;

pub(crate) trait RequestHelper {
    fn is_get_method(&self) -> bool;
    fn get_header_value(&self, header_name: &str) -> Option<&str>;
}

impl RequestHelper for httparse::Request<'_, '_> {
    fn is_get_method(&self) -> bool {
        if let Some(method) = self.method
            && method.to_lowercase() == "get"
        {
            return true;
        }
        false
    }

    fn get_header_value(&self, header_name: &str) -> Option<&str> {
        self.headers.iter().find_map(|header| {
            if header.name.to_lowercase().eq(&header_name.to_lowercase()) {
                return from_utf8(header.value).ok();
            }

            None
        })
    }
}

pub(crate) trait ResponseHelper {
    fn get_header_value(&self, header_name: &str) -> Option<&str>;
}

impl ResponseHelper for httparse::Response<'_, '_> {
    fn get_header_value(&self, header_name: &str) -> Option<&str> {
        self.headers.iter().find_map(|header| {
            if header.name.to_lowercase().eq(&header_name.to_lowercase()) {
                return from_utf8(header.value).ok();
            }

            None
        })
    }
}
