use core::fmt;

#[derive(Debug)]
pub enum DbError {
    Libsql(libsql::Error),
    Bb8(bb8::RunError<tokio_postgres::Error>),
    Postgres(tokio_postgres::Error),
}

impl core::error::Error for DbError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Libsql(e) => Some(e),
            Self::Bb8(e) => Some(e),
            Self::Postgres(e) => Some(e),
        }
    }
}

impl fmt::Display for DbError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Libsql(e) => e.fmt(f),
            Self::Bb8(e) => e.fmt(f),
            Self::Postgres(e) => e.fmt(f),
        }
    }
}

impl From<libsql::Error> for DbError {
    fn from(e: libsql::Error) -> Self {
        Self::Libsql(e)
    }
}
impl From<bb8::RunError<tokio_postgres::Error>> for DbError {
    fn from(e: bb8::RunError<tokio_postgres::Error>) -> Self {
        Self::Bb8(e)
    }
}
impl From<tokio_postgres::Error> for DbError {
    fn from(e: tokio_postgres::Error) -> Self {
        Self::Postgres(e)
    }
}
