use std::sync::Mutex;
use std::time::{Duration, Instant};

use jni::sys::{jint, jobject, jobjectArray, JNIEnv as RawJniEnv};

extern "C" {
    fn mocika_xop_pvm2_block();
    fn mocika_xop_pvm2_init(
        code: *const u8,
        code_len: usize,
        key: *const u8,
        key_len: usize,
    ) -> bool;
    fn mocika_xop_pvm2_interpret(
        env: *mut RawJniEnv,
        dex_index: jint,
        method_index: jint,
        args: jobjectArray,
    ) -> jobject;
}

pub fn initialize(code: &[u8], key: &mut [u8; 16]) -> Result<(), String> {
    let ok = unsafe { mocika_xop_pvm2_init(code.as_ptr(), code.len(), key.as_ptr(), key.len()) };
    wipe_key(key);
    if ok {
        Ok(())
    } else {
        Err("Xop PVM2 runtime initialization failed".to_string())
    }
}

pub unsafe fn interpret(
    env: *mut RawJniEnv,
    dex_index: jint,
    method_index: jint,
    args: jobjectArray,
) -> jobject {
    unsafe { mocika_xop_pvm2_interpret(env, dex_index, method_index, args) }
}

// 0 未准备、1 兼容、2 严格、3 已阻断；进程内不可恢复或切换策略。
struct Gate {
    policy: u8,
    checked: Option<Instant>,
}

impl Gate {
    fn configure(&mut self, policy: i32) -> bool {
        if (policy == 1 || policy == 2) && (self.policy == 0 || self.policy == policy as u8) {
            self.policy = policy as u8;
            true
        } else {
            self.policy = 3;
            false
        }
    }

    fn observe(&mut self, signals: i32, now: Instant) -> bool {
        self.checked = Some(now);
        if self.policy == 0 || signals & 1 != 0 || (self.policy == 2 && signals & 2 != 0) {
            self.policy = 3;
        }
        self.policy != 3
    }

    fn entry(&mut self, now: Instant, check: impl FnOnce() -> i32) -> bool {
        if self.policy == 0 || self.policy == 3 {
            return false;
        }
        if self.checked.map_or(true, |last| {
            now.duration_since(last) >= Duration::from_secs(5)
        }) {
            return self.observe(check(), now);
        }
        true
    }
}

// ponytail: 入口短锁串行合并复查，方法执行不持锁；高并发开销需设备基准后再优化。
static GATE: Mutex<Gate> = Mutex::new(Gate {
    policy: 0,
    checked: None,
});

pub fn configure_gate(policy: i32) -> bool {
    let allowed = GATE
        .lock()
        .map(|mut gate| gate.configure(policy))
        .unwrap_or(false);
    if !allowed {
        unsafe { mocika_xop_pvm2_block() };
    }
    allowed
}

pub fn observe_environment(signals: i32) -> i32 {
    let allowed = GATE
        .lock()
        .map(|mut gate| gate.observe(signals, Instant::now()))
        .unwrap_or(false);
    if allowed {
        signals
    } else {
        unsafe { mocika_xop_pvm2_block() };
        signals | 8
    }
}

pub fn method_allowed() -> bool {
    let allowed = GATE
        .lock()
        .map(|mut gate| gate.entry(Instant::now(), super::environment_signals))
        .unwrap_or(false);
    if !allowed {
        unsafe { mocika_xop_pvm2_block() };
    }
    allowed
}

pub fn wipe_key(key: &mut [u8; 16]) {
    for byte in key {
        unsafe { std::ptr::write_volatile(byte, 0) };
    }
    std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
}

#[cfg(test)]
mod gate_tests {
    use super::*;

    #[test]
    fn 入口复查节流并保持阻断不可逆() {
        let now = Instant::now();
        let mut gate = Gate {
            policy: 0,
            checked: None,
        };
        assert!(!gate.entry(now, || panic!("未准备时不能检测或放行")));
        assert!(gate.configure(1));
        assert!(gate.entry(now, || 2 | 4)); // 兼容模式不因 Root 或低置信信号阻断
        assert!(gate.entry(now + Duration::from_secs(4), || panic!(
            "窗口内不能重复扫描"
        )));
        assert!(!gate.entry(now + Duration::from_secs(5), || 1));
        assert!(!gate.configure(1));
        assert!(!gate.observe(0, now));
        assert!(!gate.entry(now, || 0));
        let mut strict = Gate {
            policy: 0,
            checked: None,
        };
        assert!(strict.configure(2));
        assert!(strict.observe(4, now));
        assert!(!strict.observe(2, now));
        let mut blocked = Gate {
            policy: 0,
            checked: None,
        };
        assert!(!blocked.configure(0));
        assert!(!blocked.configure(2));
        let mut changed = Gate {
            policy: 0,
            checked: None,
        };
        assert!(changed.configure(2));
        assert!(!changed.configure(1));
        let mut key = [0xa5; 16];
        assert!(initialize(&[], &mut key).is_err());
        assert_eq!(key, [0; 16]);
    }
}
