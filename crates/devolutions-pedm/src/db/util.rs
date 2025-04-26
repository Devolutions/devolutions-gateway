use std::fmt::Write;

/// Constructs query args like `($1, $2), ($3, $4), ($5, $6)`.
fn query_args_generic(num_records: usize, num_fields: usize, c: char) -> String {
    // 4 assumes single digits; in reality, there is reallocation because we need bigger
    let mut s = String::with_capacity(4 * num_records * num_fields);
    for i in 1..=num_records {
        s.push('(');
        for j in 1..=num_fields {
            write!(s, "{}{}, ", c, (i - 1) * num_fields + j).unwrap();
        }
        // Remove trailing space
        s.pop();
        // Remove trailing comma
        s.pop();
        write!(s, "), ").unwrap();
    }
    s.pop();
    s.pop();
    s
}

/// Constructs query args like `($1), ($2), ($3)`.
pub(crate) fn query_args_single_generic(num_records: usize, c: char) -> String {
    #[allow(clippy::arithmetic_side_effects)]
    let mut s = String::with_capacity(4 * num_records);
    for i in 1..=num_records {
        write!(s, "({c}{i}), ").unwrap();
    }
    s.pop();
    s.pop();
    s
}

/// Constructs n query args like `($1, $2, $3)`.
///
/// This is useful for `IN`.
pub(crate) fn query_args_inline_generic(num_records: usize, c: char) -> String {
    let mut s = String::with_capacity(4 * num_records);
    s.push('(');
    for i in 1..=num_records {
        #[allow(clippy::unwrap_used)]
        write!(s, "{c}{i}, ").unwrap();
    }
    // Remove trailing space.
    s.pop();
    // Remove trailing comma.
    s.pop();
    s.push(')');
    s
}

/// Constructs an insert statement for bulk inserts.
///
/// The output is like `INSERT INTO table_name (col1, col2, col3) VALUES ($1, $2, $3), ($4, $5, $6)`.
pub(crate) fn bulk_insert_statement_generic(
    table_name: &str,
    col_names: &[&str],
    num_records: usize,
    c: char,
) -> String {
    format!(
        "INSERT INTO {table_name} ({col_names}) VALUES {values}",
        col_names = col_names.join(", "),
        values = query_args_generic(num_records, col_names.len(), c)
    )
}

#[cfg(test)]
mod tests {
    use crate::db::util::query_args_single_generic;

    use super::{query_args_generic, query_args_inline_generic};

    #[test]
    fn test_query_args() {
        assert_eq!(query_args_generic(2, 2, '$'), "($1, $2), ($3, $4)".to_owned());
        assert_eq!(query_args_generic(3, 2, '$'), "($1, $2), ($3, $4), ($5, $6)".to_owned());
    }

    #[test]
    fn test_query_args_single() {
        assert_eq!(query_args_single_generic(2, '$'), "($1), ($2)".to_owned());
        assert_eq!(query_args_single_generic(3, '$'), "($1), ($2), ($3)".to_owned());
    }

    #[test]
    fn test_query_args_inline() {
        assert_eq!(query_args_inline_generic(2, '$'), "(1, 2)".to_owned());
        assert_eq!(query_args_inline_generic(3, '$'), "(1, 2, 3)".to_owned());
    }
}
