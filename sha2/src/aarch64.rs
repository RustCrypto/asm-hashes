// From sys/auxv.h
const AT_HWCAP: u64 = 16;
const HWCAP_SHA2: u64 = 64;
extern {
    fn getauxval(type_: u64) -> u64;
}

pub fn sha1_supported() -> bool {
    let hwcaps: u64 = unsafe { getauxval(AT_HWCAP) };
    (hwcaps & HWCAP_SHA2) != 0
}
