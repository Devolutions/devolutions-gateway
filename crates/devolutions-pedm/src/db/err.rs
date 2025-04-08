use core::error::Error;
use core::fmt;

#[cfg(feature = "libsql")]
use chrono::{DateTime, Utc};

#[cfg(feature = "libsql")]
use std::num::TryFromIntError;

#[cfg(feature = "postgres")]
use tokio_postgres::error::SqlState;

/// Error type for DB operations.
#[derive(Debug)]
pub enum DbError {
    #[cfg(feature = "libsql")]
    Libsql(libsql::Error),
    /// This is to handle some type conversions.
    ///
    /// For example, we may have a value that is `i16` in the data model but it is stored as `i32` in libSQL.
    #[cfg(feature = "libsql")]
    TryFromInt(TryFromIntError),
    #[cfg(feature = "libsql")]
    Timestamp(ParseTimestampError),
    #[cfg(feature = "postgres")]
    Bb8(bb8::RunError<tokio_postgres::Error>),
    #[cfg(feature = "postgres")]
    Postgres(tokio_postgres::Error),
}

impl Error for DbError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            #[cfg(feature = "libsql")]
            Self::Libsql(e) => Some(e),
            #[cfg(feature = "libsql")]
            Self::TryFromInt(e) => Some(e),
            #[cfg(feature = "libsql")]
            Self::Timestamp(e) => Some(e),
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
            #[cfg(feature = "libsql")]
            Self::TryFromInt(e) => e.fmt(f),
            #[cfg(feature = "libsql")]
            Self::Timestamp(e) => e.fmt(f),
            #[cfg(feature = "postgres")]
            Self::Bb8(e) => write!(f, "could not connect to the database: {e}"),
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
#[cfg(feature = "libsql")]
impl From<TryFromIntError> for DbError {
    fn from(e: TryFromIntError) -> Self {
        Self::TryFromInt(e)
    }
}
#[cfg(feature = "libsql")]
impl From<ParseTimestampError> for DbError {
    fn from(e: ParseTimestampError) -> Self {
        Self::Timestamp(e)
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

impl DbError {
    pub fn is_table_does_not_exist(&self) -> bool {
        match self {
            #[cfg(feature = "libsql")]
            Self::Libsql(libsql::Error::SqliteFailure(1, msg)) => msg.starts_with("no such table"),
            #[cfg(feature = "postgres")]
            Self::Postgres(e) => e.code() == Some(&SqlState::UNDEFINED_TABLE),
            _ => false,
        }
    }
}

#[cfg(feature = "libsql")]
/// A custom error type equivalent for `chrono::LocalResult`.
#[derive(Debug)]
pub enum ParseTimestampError {
    None,
    /// This should be unreachable when using UTC.
    Ambiguous(DateTime<Utc>, DateTime<Utc>),
}

#[cfg(feature = "libsql")]
impl Error for ParseTimestampError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        None
    }
}

#[cfg(feature = "libsql")]
impl fmt::Display for ParseTimestampError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::None => write!(f, "no timestamp found"),
            Self::Ambiguous(dt1, dt2) => write!(f, "ambiguous timestamp: {dt1:?} or {dt2:?}"),
        }
    }
}
