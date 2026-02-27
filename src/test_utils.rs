/// テスト用ユーティリティ
///
/// 環境変数を安全に操作するための RAII ガードを提供する。
/// テストがパニックしても Drop で自動的に元の値に復元される。
use std::sync::{Mutex, MutexGuard};

/// 全ての環境変数テストを直列化するグローバル Mutex。
/// `std::env::set_var` / `remove_var` はプロセスグローバルな操作のため、
/// 環境変数名が異なっても単一の Mutex で保護する（安全側に倒す）。
static ENV_MUTEX: Mutex<()> = Mutex::new(());

/// `ENV_MUTEX` のロックを保持していることを型レベルで証明する newtype ガード。
///
/// `env_lock()` でのみ取得でき、`TempEnvVar` のコンストラクタに渡すことで
/// 無関係な `Mutex<()>` のガードが誤って使われることを防ぐ。
pub struct EnvLock<'a>(MutexGuard<'a, ()>);

/// `ENV_MUTEX` をロックし、`EnvLock` ガードを返す。
///
/// # Panics
/// Mutex が poisoned の場合にパニックする。
pub fn env_lock() -> EnvLock<'static> {
    EnvLock(ENV_MUTEX.lock().unwrap())
}

/// 環境変数を一時的に設定し、Drop 時に元の値（または未設定状態）に復元する RAII ガード。
///
/// `EnvLock` の参照をコンストラクタで要求することで、`ENV_MUTEX` のロック保持を
/// コンパイル時に強制する。ライフタイム `'lock` により、`TempEnvVar` が存在する間は
/// `EnvLock` がドロップされない。
///
/// # 使い方
/// ```ignore
/// let lock = env_lock();
/// let _guard = TempEnvVar::set(&lock, "MY_VAR", "value");
/// // MY_VAR == "value"
/// // _guard が Drop されると MY_VAR は元の状態に戻る
/// // lock は _guard より後に Drop される（宣言順序の逆順）
/// ```
pub struct TempEnvVar<'lock> {
    key: String,
    original: Option<String>,
    _lock: std::marker::PhantomData<&'lock ()>,
}

impl<'lock> TempEnvVar<'lock> {
    /// 環境変数を設定し、ガードを返す。
    /// ガードが Drop されると元の値に復元される。
    ///
    /// `EnvLock` の参照を要求することで、`ENV_MUTEX` のロック保持をコンパイル時に強制する。
    pub fn set(_guard: &'lock EnvLock<'_>, key: &str, value: &str) -> Self {
        let original = std::env::var(key).ok();
        // SAFETY: ENV_MUTEX のロック保持が EnvLock パラメータにより保証されている
        unsafe { std::env::set_var(key, value) };
        Self {
            key: key.to_string(),
            original,
            _lock: std::marker::PhantomData,
        }
    }

    /// 環境変数を削除し、ガードを返す。
    /// ガードが Drop されると元の値に復元される。
    ///
    /// `EnvLock` の参照を要求することで、`ENV_MUTEX` のロック保持をコンパイル時に強制する。
    pub fn remove(_guard: &'lock EnvLock<'_>, key: &str) -> Self {
        let original = std::env::var(key).ok();
        // SAFETY: ENV_MUTEX のロック保持が EnvLock パラメータにより保証されている
        unsafe { std::env::remove_var(key) };
        Self {
            key: key.to_string(),
            original,
            _lock: std::marker::PhantomData,
        }
    }
}

impl Drop for TempEnvVar<'_> {
    fn drop(&mut self) {
        // SAFETY: ENV_MUTEX のロック保持がライフタイムにより保証されている
        // （EnvLock は TempEnvVar より後に Drop される）
        match &self.original {
            Some(val) => unsafe { std::env::set_var(&self.key, val) },
            None => unsafe { std::env::remove_var(&self.key) },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_temp_env_var_set_and_restore() {
        let lock = env_lock();

        // 初期状態: 未設定
        let _cleanup = TempEnvVar::remove(&lock, "TEST_SAFE_DOCKER_TEMP_VAR");
        assert!(std::env::var("TEST_SAFE_DOCKER_TEMP_VAR").is_err());

        {
            let _guard = TempEnvVar::set(&lock, "TEST_SAFE_DOCKER_TEMP_VAR", "hello");
            assert_eq!(std::env::var("TEST_SAFE_DOCKER_TEMP_VAR").unwrap(), "hello");
        }
        // ガード Drop 後、元の未設定状態に戻る
        assert!(std::env::var("TEST_SAFE_DOCKER_TEMP_VAR").is_err());
    }

    #[test]
    fn test_temp_env_var_remove_and_restore() {
        let lock = env_lock();

        // 初期状態: 設定済み
        let _outer = TempEnvVar::set(&lock, "TEST_SAFE_DOCKER_TEMP_VAR2", "original");

        {
            let _guard = TempEnvVar::remove(&lock, "TEST_SAFE_DOCKER_TEMP_VAR2");
            assert!(std::env::var("TEST_SAFE_DOCKER_TEMP_VAR2").is_err());
        }
        // ガード Drop 後、元の値に戻る
        assert_eq!(
            std::env::var("TEST_SAFE_DOCKER_TEMP_VAR2").unwrap(),
            "original"
        );
    }

    #[test]
    fn test_temp_env_var_overwrite_and_restore() {
        let lock = env_lock();

        let _outer = TempEnvVar::set(&lock, "TEST_SAFE_DOCKER_TEMP_VAR3", "first");
        assert_eq!(
            std::env::var("TEST_SAFE_DOCKER_TEMP_VAR3").unwrap(),
            "first"
        );

        {
            let _guard = TempEnvVar::set(&lock, "TEST_SAFE_DOCKER_TEMP_VAR3", "second");
            assert_eq!(
                std::env::var("TEST_SAFE_DOCKER_TEMP_VAR3").unwrap(),
                "second"
            );
        }
        // guard Drop 後、"first" に戻る
        assert_eq!(
            std::env::var("TEST_SAFE_DOCKER_TEMP_VAR3").unwrap(),
            "first"
        );
    }
}
