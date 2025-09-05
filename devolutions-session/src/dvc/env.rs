use std::collections::HashMap;

pub(crate) fn make_environment_block(env: HashMap<String, String>) -> anyhow::Result<Vec<u16>> {
    let ensure_no_nulls = |s: &str| {
        if s.contains('\0') {
            return Err(anyhow::anyhow!("Environment variable contains null byte"));
        }
        Ok(())
    };

    // Windows environment block is a sequence of null-terminated
    // "key=value" strings, terminated by an additional null character.
    let mut block = Vec::<u16>::new();

    // Keep existing user environment variables (e.g. APPDATA, USERPROFILE, etc.)
    for (key, value) in std::env::vars().chain(env.into_iter()) {
        ensure_no_nulls(&key)?;
        ensure_no_nulls(&value)?;

        block.extend(key.encode_utf16());
        block.extend("=".encode_utf16());
        block.extend(value.encode_utf16());
        block.push(0); // Null terminator for each variable
    }

    if block.is_empty() {
        return Ok(vec![0; 2]);
    }

    block.push(0); // Additional null terminator at the end of the block

    Ok(block)
}
