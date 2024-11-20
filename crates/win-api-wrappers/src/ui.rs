use windows::Win32::UI::WindowsAndMessaging::MESSAGEBOX_RESULT;

#[repr(i32)]
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum MessageBoxResult {
    Ok = windows::Win32::UI::WindowsAndMessaging::IDOK.0,
    Cancel = windows::Win32::UI::WindowsAndMessaging::IDCANCEL.0,
    Abort = windows::Win32::UI::WindowsAndMessaging::IDABORT.0,
    Retry = windows::Win32::UI::WindowsAndMessaging::IDRETRY.0,
    Ignore = windows::Win32::UI::WindowsAndMessaging::IDIGNORE.0,
    Yes = windows::Win32::UI::WindowsAndMessaging::IDYES.0,
    No = windows::Win32::UI::WindowsAndMessaging::IDNO.0,
    Continue = windows::Win32::UI::WindowsAndMessaging::IDCONTINUE.0,
    TryAgain = windows::Win32::UI::WindowsAndMessaging::IDTRYAGAIN.0,
    Async = windows::Win32::UI::WindowsAndMessaging::IDASYNC.0,
    Timeout = windows::Win32::UI::WindowsAndMessaging::IDTIMEOUT.0,
}

impl TryFrom<MESSAGEBOX_RESULT> for MessageBoxResult {
    type Error = anyhow::Error;

    fn try_from(v: MESSAGEBOX_RESULT) -> Result<Self, Self::Error> {
        match v {
            windows::Win32::UI::WindowsAndMessaging::IDOK => Ok(MessageBoxResult::Ok),
            windows::Win32::UI::WindowsAndMessaging::IDCANCEL => Ok(MessageBoxResult::Cancel),
            windows::Win32::UI::WindowsAndMessaging::IDABORT => Ok(MessageBoxResult::Abort),
            windows::Win32::UI::WindowsAndMessaging::IDRETRY => Ok(MessageBoxResult::Retry),
            windows::Win32::UI::WindowsAndMessaging::IDIGNORE => Ok(MessageBoxResult::Ignore),
            windows::Win32::UI::WindowsAndMessaging::IDYES => Ok(MessageBoxResult::Yes),
            windows::Win32::UI::WindowsAndMessaging::IDNO => Ok(MessageBoxResult::No),
            windows::Win32::UI::WindowsAndMessaging::IDCONTINUE => Ok(MessageBoxResult::Continue),
            windows::Win32::UI::WindowsAndMessaging::IDTRYAGAIN => Ok(MessageBoxResult::TryAgain),
            windows::Win32::UI::WindowsAndMessaging::IDASYNC => Ok(MessageBoxResult::Async),
            windows::Win32::UI::WindowsAndMessaging::IDTIMEOUT => Ok(MessageBoxResult::Timeout),
            _ => Err(anyhow::anyhow!("Invalid MESSAGEBOX_RESULT: {}", v.0)),
        }
    }
}
