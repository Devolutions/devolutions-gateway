use windows::core::PWSTR;
use windows::Win32::Foundation::HINSTANCE;
use windows::Win32::UI::WindowsAndMessaging::LoadStringW;

pub fn load_string(hinstance: HINSTANCE, resource_id: u32) -> anyhow::Result<Option<String>, windows::core::Error> {
    let mut resource_ptr: PWSTR = PWSTR::null();

    // SAFETY:
    // The use of `std::mem::transmute` here provides compatibility between `&mut PWSTR` and the raw pointer type expected by `LoadStringW`.
    // - This is sound because `&mut PWSTR` has the same memory layout as the pointer type expected by `LoadStringW`.
    let resource_ptr_addr = unsafe { std::mem::transmute::<&mut PWSTR, PWSTR>(&mut resource_ptr) };

    // SAFETY:
    // No preconditions. An invalid `hinstance` or `resource_id` will cause `LoadStringW` to return 0.
    // We pass a null-initialized mutable reference to `resource_ptr`. This is safe because:
    // - `resource_ptr` is a properly aligned, initialized `PWSTR` variable that is of sufficient length to hold a pointer.
    // - if `cchBufferMax` is equal to 0, `LoadStringW` guarantees to write a valid pointer to the start of a resource string or leave it as null if no resource is found.
    let length = unsafe { LoadStringW(Some(hinstance), resource_id, resource_ptr_addr, 0) };

    match length {
        0 => Ok(None),
        _ => {
            // SAFETY:
            // `LoadStringW` guarantees that:
            // - It will return 0 on failure or the length of the string resource in characters
            // - If the function succeeds (`length > 0`), `resource_ptr.0` will point to a valid UTF-16 string resource
            // and be valid for reading `length` UTF-16 code units
            // - The memory is owned by the Windows resource system and must not be deallocated or modified
            // No attempt should be made to mutate or access `slice` beyond it's bounds
            let slice = unsafe {
                std::slice::from_raw_parts(
                    resource_ptr.0.cast_const(),
                    usize::try_from(length).expect("i32-to-usize"),
                )
            };

            Ok(Some(String::from_utf16_lossy(slice)))
        }
    }
}
