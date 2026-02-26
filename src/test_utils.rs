/// テスト用ユーティリティ
///
/// 環境変数を安全に操作するための RAII ガードを提供する。
/// テストがパニックしても Drop で自動的に元の値に復元される。
use std::sync::Mutex;

/// 全ての環境変数テストを直列化するグローバル Mutex。
/// `std::env::set_var` / `remove_var` はプロセスグローバルな操作のため、
/// 環境変数名が異なっても単一の Mutex で保護する（安全側に倒す）。
pub static ENV_MUTEX: Mutex<()> = Mutex::new(());

/// 環境変数を一時的に設定し、Drop 時に元の値（または未設定状態）に復元する RAII ガード。
///
/// # 使い方
/// ```ignore
/// let _lock = ENV_MUTEX.lock().unwrap();
/// let _guard = TempEnvVar::set("MY_VAR", "value");
/// // MY_VAR == "value"
/// // _guard が Drop されると MY_VAR は元の状態に戻る
/// ```
pub struct TempEnvVar {
    key: String,
    original: Option<String>,
}

impl TempEnvVar {
    /// 環境変数を設定し、ガードを返す。
    /// ガードが Drop されると元の値に復元される。
    ///
    /// 呼び出し元が `ENV_MUTEX` をロックしていることを前提とする。
    pub fn set(key: &str, value: &str) -> Self {
        let original = std::env::var(key).ok();
        // SAFETY: ENV_MUTEX で直列化済みであることを呼び出し元が保証する
        unsafe { std::env::set_var(key, value) };
        Self {
            key: key.to_string(),
            original,
        }
    }

    /// 環境変数を削除し、ガードを返す。
    /// ガードが Drop されると元の値に復元される。
    ///
    /// 呼び出し元が `ENV_MUTEX` をロックしていることを前提とする。
    pub fn remove(key: &str) -> Self {
        let original = std::env::var(key).ok();
        // SAFETY: ENV_MUTEX で直列化済みであることを呼び出し元が保証する
        unsafe { std::env::remove_var(key) };
        Self {
            key: key.to_string(),
            original,
        }
    }
}

impl Drop for TempEnvVar {
    fn drop(&mut self) {
        // SAFETY: ENV_MUTEX のロック保持中に Drop される（スコープの順序による保証）
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
        let _lock = ENV_MUTEX.lock().unwrap();

        // 初期状態: 未設定
        let _cleanup = TempEnvVar::remove("TEST_SAFE_DOCKER_TEMP_VAR");
        assert!(std::env::var("TEST_SAFE_DOCKER_TEMP_VAR").is_err());

        {
            let _guard = TempEnvVar::set("TEST_SAFE_DOCKER_TEMP_VAR", "hello");
            assert_eq!(std::env::var("TEST_SAFE_DOCKER_TEMP_VAR").unwrap(), "hello");
        }
        // ガード Drop 後、元の未設定状態に戻る
        assert!(std::env::var("TEST_SAFE_DOCKER_TEMP_VAR").is_err());
    }

    #[test]
    fn test_temp_env_var_remove_and_restore() {
        let _lock = ENV_MUTEX.lock().unwrap();

        // 初期状態: 設定済み
        let _outer = TempEnvVar::set("TEST_SAFE_DOCKER_TEMP_VAR2", "original");

        {
            let _guard = TempEnvVar::remove("TEST_SAFE_DOCKER_TEMP_VAR2");
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
        let _lock = ENV_MUTEX.lock().unwrap();

        let _outer = TempEnvVar::set("TEST_SAFE_DOCKER_TEMP_VAR3", "first");
        assert_eq!(
            std::env::var("TEST_SAFE_DOCKER_TEMP_VAR3").unwrap(),
            "first"
        );

        {
            let _guard = TempEnvVar::set("TEST_SAFE_DOCKER_TEMP_VAR3", "second");
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
