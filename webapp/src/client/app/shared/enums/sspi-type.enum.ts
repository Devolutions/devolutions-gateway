enum SSPIType {
  Kerberos = 0,
  Negotiate = 1,
  Ntlm = 2,
}

namespace SSPIType {
  export function getEnumKey(value: SSPIType): string {
    return SSPIType[value];
  }
}
export { SSPIType };
