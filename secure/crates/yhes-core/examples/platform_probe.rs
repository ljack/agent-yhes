//! Disposable Data Protection keychain probe for the signed engine identity.
//!
//! Build this example, replace only the executable in a temporary copy of the
//! provisioned Engine.app, and run that signed bundle. It never prints key
//! material. Cleanup deletes only the exact accounts this process created.

fn main() {
    #[cfg(not(target_os = "macos"))]
    {
        eprintln!("fail unsupported-platform");
        std::process::exit(1);
    }
    #[cfg(target_os = "macos")]
    {
        let mut guard = macos::Guard::new();
        let outcome = macos::run(&mut guard);
        let cleanup = guard.finish();
        macos::report(outcome, cleanup);
    }
}

#[cfg(target_os = "macos")]
mod macos {
    use std::fs;
    use std::io::Read;
    use std::path::PathBuf;
    use std::ptr;

    use yhes_core::keys::{
        Anchor, AnchorStore, KeyProvider, PlatformKeychain, ANCHOR_SERVICE, VAULT_SERVICE,
    };
    use yhes_core::store::Vault;
    use yhes_core::Error;

    const GROUP: &str = "25C9H9N953.com.agent-yhes.engine.vault";
    const APPLICATION_ID: &str = "25C9H9N953.com.agent-yhes.engine";
    const NOT_FOUND: i32 = -25300;

    pub struct Guard {
        items: Vec<(&'static str, String)>,
        finished: bool,
    }

    pub struct Cleanup {
        pub cleaned: usize,
        pub leftovers: Vec<String>,
        pub status: i32,
    }

    impl Guard {
        pub fn new() -> Self {
            Self {
                items: Vec::new(),
                finished: false,
            }
        }

        fn arm(&mut self, service: &'static str, account: String) {
            if !self
                .items
                .iter()
                .any(|(existing, name)| *existing == service && name == &account)
            {
                self.items.push((service, account));
            }
        }

        pub fn finish(&mut self) -> Cleanup {
            self.finished = true;
            let mut cleaned = 0usize;
            let mut leftovers = Vec::new();
            let mut status = 0i32;
            for (service, account) in self.items.drain(..) {
                let deleted = delete_exact(service, &account);
                if deleted == 0 {
                    cleaned += 1;
                } else if deleted != NOT_FOUND {
                    status = deleted;
                    leftovers.push(format!("{service}/{account}"));
                    continue;
                }
                let after = exists_exact(service, &account);
                if after != NOT_FOUND {
                    status = after;
                    let label = format!("{service}/{account}");
                    if !leftovers.contains(&label) {
                        leftovers.push(label);
                    }
                }
            }
            Cleanup {
                cleaned,
                leftovers,
                status,
            }
        }
    }

    impl Drop for Guard {
        fn drop(&mut self) {
            if self.finished || self.items.is_empty() {
                return;
            }
            let cleanup = self.finish();
            if !cleanup.leftovers.is_empty() {
                eprintln!(
                    "fail cleanup status={} leftover={}",
                    cleanup.status,
                    cleanup.leftovers.join(",")
                );
            }
        }
    }

    pub fn report(outcome: Result<(), String>, cleanup: Cleanup) {
        if !cleanup.leftovers.is_empty() {
            eprintln!(
                "fail cleanup status={} leftover={} cleaned={}",
                cleanup.status,
                cleanup.leftovers.join(","),
                cleanup.cleaned
            );
            std::process::exit(1);
        }
        match outcome {
            Ok(()) => println!("pass cleaned={}", cleanup.cleaned),
            Err(reason) => {
                eprintln!("fail {reason} cleaned={}", cleanup.cleaned);
                std::process::exit(1);
            }
        }
    }

    pub fn run(guard: &mut Guard) -> Result<(), String> {
        if let Err(status) = entitlements_match() {
            return Err(format!("entitlement status={status}"));
        }
        let nonce = nonce()?;
        let vault_account = format!("probev{nonce}");
        let anchor_account = format!("probea{nonce}");
        let planned = [
            (VAULT_SERVICE, vault_account.clone()),
            (ANCHOR_SERVICE, format!("g1:{vault_account}")),
            (ANCHOR_SERVICE, format!("h1:{vault_account}")),
            (ANCHOR_SERVICE, format!("g1:{anchor_account}")),
            (ANCHOR_SERVICE, format!("h1:{anchor_account}")),
            (ANCHOR_SERVICE, format!("a1:{anchor_account}:1")),
        ];
        for (service, account) in &planned {
            let status = exists_exact(service, account);
            if status != NOT_FOUND {
                return Err(format!("pre-existing status={status}"));
            }
        }

        exercise_anchors(guard, &anchor_account)?;
        exercise_vault(guard, &vault_account)?;
        Ok(())
    }

    fn exercise_anchors(guard: &mut Guard, account: &str) -> Result<(), String> {
        let store = PlatformKeychain;
        match AnchorStore::load(&store, account) {
            Ok(None) => {}
            Ok(Some(_)) => return Err("anchor-load-empty".into()),
            Err(error) => return Err(format!("anchor-load-empty {error}")),
        }
        let genesis = anchor(0, "11");
        let other_genesis = anchor(0, "22");
        guard.arm(ANCHOR_SERVICE, format!("g1:{account}"));
        guard.arm(ANCHOR_SERVICE, format!("h1:{account}"));
        store
            .advance(account, None, &genesis)
            .map_err(|error| format!("anchor-genesis {error}"))?;
        expect_loaded(&store, account, &genesis, "anchor-load")?;
        store
            .advance(account, None, &genesis)
            .map_err(|error| format!("anchor-retry {error}"))?;
        match store.advance(account, None, &other_genesis) {
            Err(Error::Conflict(message)) if message == "checkpoint already exists" => {}
            Ok(()) => return Err("anchor-conflict-accepted".into()),
            Err(error) => return Err(format!("anchor-conflict {error}")),
        }
        match store.advance(account, Some(&genesis), &other_genesis) {
            Err(Error::Conflict(message)) if message == "checkpoint mismatch" => {}
            Ok(()) => return Err("anchor-mismatch-accepted".into()),
            Err(error) => return Err(format!("anchor-mismatch {error}")),
        }
        expect_loaded(&store, account, &genesis, "anchor-load-after-conflict")?;

        let next = anchor(1, "33");
        let other_next = anchor(1, "44");
        guard.arm(ANCHOR_SERVICE, format!("a1:{account}:1"));
        store
            .advance(account, Some(&genesis), &next)
            .map_err(|error| format!("anchor-successor {error}"))?;
        store
            .advance(account, Some(&genesis), &next)
            .map_err(|error| format!("anchor-successor-retry {error}"))?;
        match store.advance(account, Some(&genesis), &other_next) {
            Err(Error::Conflict(message)) if message == "checkpoint mismatch" => {}
            Ok(()) => return Err("anchor-successor-conflict-accepted".into()),
            Err(error) => return Err(format!("anchor-successor-conflict {error}")),
        }
        expect_loaded(&store, account, &next, "anchor-head")?;
        Ok(())
    }

    fn exercise_vault(guard: &mut Guard, account: &str) -> Result<(), String> {
        let provider = PlatformKeychain;
        guard.arm(VAULT_SERVICE, account.to_owned());
        let created = provider
            .create(account)
            .map_err(|error| format!("key-create {error}"))?;
        guard.arm(ANCHOR_SERVICE, format!("g1:{account}"));
        guard.arm(ANCHOR_SERVICE, format!("h1:{account}"));
        let directory = vault_dir()?;
        let path = directory.join("vault.db");
        {
            let vault = Vault::create(
                &path,
                &created,
                "probe",
                account,
                Box::new(PlatformKeychain),
            )
            .map_err(|error| format!("vault-create {error}"))?;
            drop(vault);
        }
        drop(created);
        let loaded =
            KeyProvider::load(&provider, account).map_err(|error| format!("key-load {error}"))?;
        {
            let vault = Vault::open(&path, &loaded, "probe", account, Box::new(PlatformKeychain))
                .map_err(|error| format!("vault-reopen {error}"))?;
            drop(vault);
        }
        drop(loaded);
        match provider.create(account) {
            Err(Error::Conflict(message)) if message == "vault key reference already exists" => {}
            Ok(key) => {
                drop(key);
                return Err("duplicate-key-accepted".into());
            }
            Err(error) => return Err(format!("duplicate-key {error}")),
        }
        let _ = fs::remove_dir_all(&directory);
        Ok(())
    }

    fn expect_loaded(
        store: &PlatformKeychain,
        account: &str,
        expected: &Anchor,
        label: &str,
    ) -> Result<(), String> {
        match AnchorStore::load(store, account) {
            Ok(Some(found)) if found == *expected => Ok(()),
            Ok(Some(_)) => Err(format!("{label} different-head")),
            Ok(None) => Err(format!("{label} missing")),
            Err(error) => Err(format!("{label} {error}")),
        }
    }

    fn anchor(revision: u64, byte: &str) -> Anchor {
        Anchor {
            revision,
            digest: byte.repeat(32),
        }
    }

    fn nonce() -> Result<String, String> {
        let mut bytes = [0u8; 16];
        fs::File::open("/dev/urandom")
            .and_then(|mut file| file.read_exact(&mut bytes))
            .map_err(|_| "nonce unavailable".to_owned())?;
        Ok(bytes.iter().map(|byte| format!("{byte:02x}")).collect())
    }

    fn vault_dir() -> Result<PathBuf, String> {
        let mut bytes = [0u8; 8];
        fs::File::open("/dev/urandom")
            .and_then(|mut file| file.read_exact(&mut bytes))
            .map_err(|_| "vault directory unavailable".to_owned())?;
        let name: String = bytes.iter().map(|byte| format!("{byte:02x}")).collect();
        // Vault::create rejects any symlink ancestor. /tmp and /var are symlinks.
        let path = PathBuf::from(format!("/private/tmp/yhes-platform-probe-{name}"));
        fs::create_dir(&path).map_err(|_| "vault directory unavailable".to_owned())?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(&path, fs::Permissions::from_mode(0o700));
        }
        Ok(path)
    }

    fn entitlements_match() -> Result<(), i32> {
        unsafe {
            let task = SecTaskCreateFromSelf(ptr::null());
            if task.is_null() {
                return Err(-1);
            }
            let group_ok = entitlement_equals(task, "keychain-access-groups", GROUP, true);
            let app_ok = entitlement_equals(
                task,
                "com.apple.application-identifier",
                APPLICATION_ID,
                false,
            );
            CFRelease(task);
            match (group_ok, app_ok) {
                (Ok(()), Ok(())) => Ok(()),
                (Err(status), _) | (_, Err(status)) => Err(status),
            }
        }
    }

    unsafe fn entitlement_equals(
        task: *const std::ffi::c_void,
        name: &str,
        expected: &str,
        array: bool,
    ) -> Result<(), i32> {
        let key = cf_string(name);
        let mut error = ptr::null();
        let value = SecTaskCopyValueForEntitlement(task, key, &mut error);
        CFRelease(key);
        if value.is_null() {
            let status = if error.is_null() {
                -1
            } else {
                let code = CFErrorGetCode(error);
                CFRelease(error);
                code as i32
            };
            return Err(status);
        }
        let wanted = cf_string(expected);
        let ok = if array {
            CFGetTypeID(value) == CFArrayGetTypeID()
                && CFArrayGetCount(value) == 1
                && CFEqual(CFArrayGetValueAtIndex(value, 0), wanted) != 0
        } else {
            CFGetTypeID(value) == CFStringGetTypeID() && CFEqual(value, wanted) != 0
        };
        CFRelease(wanted);
        CFRelease(value);
        if ok {
            Ok(())
        } else {
            Err(-2)
        }
    }

    fn exists_exact(service: &str, account: &str) -> i32 {
        let mut result = ptr::null();
        let query = item_query(service, account, true);
        let status = unsafe { SecItemCopyMatching(query, &mut result) };
        unsafe {
            CFRelease(query);
            if !result.is_null() {
                CFRelease(result);
            }
        }
        status
    }

    fn delete_exact(service: &str, account: &str) -> i32 {
        let query = item_query(service, account, false);
        let status = unsafe { SecItemDelete(query) };
        unsafe { CFRelease(query) };
        status
    }

    fn item_query(service: &str, account: &str, attributes: bool) -> *const std::ffi::c_void {
        unsafe {
            let service_value = cf_string(service);
            let account_value = cf_string(account);
            let group_value = cf_string(GROUP);
            let limit_value = cf_number(1);
            let mut keys = vec![
                kSecClass,
                kSecAttrService,
                kSecAttrAccount,
                kSecAttrAccessGroup,
                kSecAttrSynchronizable,
                kSecUseDataProtectionKeychain,
            ];
            let mut values = vec![
                kSecClassGenericPassword,
                service_value,
                account_value,
                group_value,
                kCFBooleanFalse,
                kCFBooleanTrue,
            ];
            if attributes {
                keys.push(kSecReturnAttributes);
                values.push(kCFBooleanTrue);
                keys.push(kSecMatchLimit);
                values.push(limit_value);
            }
            let dictionary = CFDictionaryCreate(
                ptr::null(),
                keys.as_ptr(),
                values.as_ptr(),
                keys.len() as isize,
                &kCFTypeDictionaryKeyCallBacks,
                &kCFTypeDictionaryValueCallBacks,
            );
            CFRelease(service_value);
            CFRelease(account_value);
            CFRelease(group_value);
            CFRelease(limit_value);
            dictionary
        }
    }

    fn cf_string(value: &str) -> *const std::ffi::c_void {
        unsafe {
            CFStringCreateWithBytes(
                ptr::null(),
                value.as_ptr(),
                value.len() as isize,
                0x0800_0100,
                0,
            )
        }
    }

    fn cf_number(value: i64) -> *const std::ffi::c_void {
        unsafe { CFNumberCreate(ptr::null(), 4, &value) }
    }

    #[link(name = "CoreFoundation", kind = "framework")]
    extern "C" {
        static kCFBooleanTrue: *const std::ffi::c_void;
        static kCFBooleanFalse: *const std::ffi::c_void;
        static kCFTypeDictionaryKeyCallBacks: u8;
        static kCFTypeDictionaryValueCallBacks: u8;
        fn CFStringCreateWithBytes(
            allocator: *const std::ffi::c_void,
            bytes: *const u8,
            length: isize,
            encoding: u32,
            is_external: u8,
        ) -> *const std::ffi::c_void;
        fn CFNumberCreate(
            allocator: *const std::ffi::c_void,
            kind: i32,
            value: *const i64,
        ) -> *const std::ffi::c_void;
        fn CFDictionaryCreate(
            allocator: *const std::ffi::c_void,
            keys: *const *const std::ffi::c_void,
            values: *const *const std::ffi::c_void,
            count: isize,
            key_callbacks: *const u8,
            value_callbacks: *const u8,
        ) -> *const std::ffi::c_void;
        fn CFRelease(value: *const std::ffi::c_void);
        fn CFEqual(left: *const std::ffi::c_void, right: *const std::ffi::c_void) -> u8;
        fn CFGetTypeID(value: *const std::ffi::c_void) -> usize;
        fn CFArrayGetTypeID() -> usize;
        fn CFStringGetTypeID() -> usize;
        fn CFArrayGetCount(array: *const std::ffi::c_void) -> isize;
        fn CFArrayGetValueAtIndex(
            array: *const std::ffi::c_void,
            index: isize,
        ) -> *const std::ffi::c_void;
        fn CFErrorGetCode(error: *const std::ffi::c_void) -> isize;
    }

    #[link(name = "Security", kind = "framework")]
    extern "C" {
        static kSecClass: *const std::ffi::c_void;
        static kSecClassGenericPassword: *const std::ffi::c_void;
        static kSecAttrService: *const std::ffi::c_void;
        static kSecAttrAccount: *const std::ffi::c_void;
        static kSecAttrAccessGroup: *const std::ffi::c_void;
        static kSecAttrSynchronizable: *const std::ffi::c_void;
        static kSecUseDataProtectionKeychain: *const std::ffi::c_void;
        static kSecReturnAttributes: *const std::ffi::c_void;
        static kSecMatchLimit: *const std::ffi::c_void;
        fn SecItemCopyMatching(
            query: *const std::ffi::c_void,
            result: *mut *const std::ffi::c_void,
        ) -> i32;
        fn SecItemDelete(query: *const std::ffi::c_void) -> i32;
        fn SecTaskCreateFromSelf(allocator: *const std::ffi::c_void) -> *const std::ffi::c_void;
        fn SecTaskCopyValueForEntitlement(
            task: *const std::ffi::c_void,
            entitlement: *const std::ffi::c_void,
            error: *mut *const std::ffi::c_void,
        ) -> *const std::ffi::c_void;
    }
}
