//! OS resource setup corresponding to Python's setup_files_limit().
#[cfg(unix)]
pub fn raise_file_limit() -> std::io::Result<(u64, u64)> {
    // SAFETY: both libc calls use a valid, initialized rlimit structure; the
    // hard limit is preserved and only this process's soft limit is changed.
    unsafe {
        let mut limit = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        if libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) != 0 {
            return Err(std::io::Error::last_os_error());
        }
        let old = limit.rlim_cur;
        limit.rlim_cur = limit.rlim_max;
        if libc::setrlimit(libc::RLIMIT_NOFILE, &limit) != 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok((old, limit.rlim_cur))
    }
}

pub fn setup_file_limit() {
    #[cfg(unix)]
    match raise_file_limit() {
        Ok((old, new)) => tracing::debug!(old, new, "文件描述符软上限已提高到硬上限"),
        Err(error) => tracing::warn!(%error, "无法提高文件描述符上限，继续使用系统现有设置"),
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    #[test]
    fn raise_limit_in_subprocess_only() {
        const CHILD: &str = "MTPROTO_RLIMIT_TEST_CHILD";
        if std::env::var_os(CHILD).is_none() {
            let result = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["system::tests::raise_limit_in_subprocess_only", "--exact"])
                .env(CHILD, "1")
                .status()
                .unwrap();
            assert!(result.success());
            return;
        }
        // SAFETY: a valid struct is passed; only the isolated child lowers its
        // soft limit. The hard limit and parent test runner remain untouched.
        unsafe {
            let mut limit = libc::rlimit {
                rlim_cur: 0,
                rlim_max: 0,
            };
            assert_eq!(libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit), 0);
            let hard = limit.rlim_max;
            limit.rlim_cur = 64.min(hard);
            assert_eq!(libc::setrlimit(libc::RLIMIT_NOFILE, &limit), 0);
            let (old, new) = raise_file_limit().unwrap();
            assert_eq!(old, limit.rlim_cur);
            assert_eq!(new, hard);
            assert_eq!(libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit), 0);
            assert_eq!(limit.rlim_cur, limit.rlim_max);
        }
    }
}
