use core::fmt;

#[derive(Debug)]
pub enum DbError {
    #[cfg(feature = "libsql")]
    Libsql(libsql::Error),
    #[cfg(feature = "postgres")]
    Bb8(bb8::RunError<tokio_postgres::Error>),
    #[cfg(feature = "postgres")]
    Postgres(tokio_postgres::Error),
}

impl core::error::Error for DbError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            #[cfg(feature = "libsql")]
            Self::Libsql(e) => Some(e),
            #[cfg(feature = "postgres")]
            Self::Bb8(e) => Some(e),
            #[cfg(feature = "postgres")]
            Self::Postgres(e) => Some(e),
        }
    }
}

impl fmt::Display for DbError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            #[cfg(feature = "libsql")]
            Self::Libsql(e) => e.fmt(f),
            #[cfg(feature = "postgres")]
            Self::Bb8(e) => e.fmt(f),
            #[cfg(feature = "postgres")]
            Self::Postgres(e) => e.fmt(f),
        }
    }
}

#[cfg(feature = "libsql")]
impl From<libsql::Error> for DbError {
    fn from(e: libsql::Error) -> Self {
        Self::Libsql(e)
    }
}

#[cfg(feature = "postgres")]
impl From<bb8::RunError<tokio_postgres::Error>> for DbError {
    fn from(e: bb8::RunError<tokio_postgres::Error>) -> Self {
        Self::Bb8(e)
    }
}
#[cfg(feature = "postgres")]
impl From<tokio_postgres::Error> for DbError {
    fn from(e: tokio_postgres::Error) -> Self {
        Self::Postgres(e)
    }
}
