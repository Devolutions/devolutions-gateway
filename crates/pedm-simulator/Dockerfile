# Use a Windows Server Core base image.
FROM mcr.microsoft.com/windows/servercore:ltsc2022

# Use PowerShell for RUN commands.
SHELL ["powershell", "-Command", "$ErrorActionPreference = 'Stop'; $ProgressPreference = 'SilentlyContinue';"]

# Download & Install Visual C++ Redistributable
RUN [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; \
    Invoke-WebRequest "https://aka.ms/vs/17/release/vc_redist.x64.exe" -OutFile "vc_redist.x64.exe"; \
    Start-Process -filepath C:\vc_redist.x64.exe -ArgumentList "/install", "/passive", "/norestart" -Passthru | Wait-Process; \
    Remove-Item -Force vc_redist.x64.exe;

# Copy the PEDM simulator binary.
COPY artifacts/pedm-simulator.exe C:

# Clang runtime for ASAN memory sanitizer is required because we build pedm_simulator with -Zsanitizer=address.
COPY artifacts/clang_rt.asan_dynamic-x86_64.dll C:

# Set the simulator executable as the entry point.
ENTRYPOINT ["C:\\pedm-simulator.exe"]
