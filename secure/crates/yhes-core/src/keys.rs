//! Storage keys are distinct from the human device signing key.
//!
//! Platform storage is the Data Protection keychain, scoped to the signed
//! engine identity. Checkpoint history is add-only. See `docs/KEY-CUSTODY.md`.
//! Tests never call the platform path.

use crate::{Error, Result};
use rand::{rngs::OsRng, RngCore};
use zeroize::{Zeroize, Zeroizing};

#[path = "anchor.rs"]
pub mod anchor;

pub use anchor::{Anchor, AnchorStore};

pub const ENGINE_IDENTIFIER: &str = "com.agent-yhes.engine";
pub const VAULT_ACCESS_GROUP_NAME: &str = "com.agent-yhes.engine.vault";
pub const VAULT_SERVICE: &str = "com.agent-yhes.vault.v1";
pub const ANCHOR_SERVICE: &str = "com.agent-yhes.anchor.v1";

const CS_VALID: u32 = 0x0000_0001;
const CS_ADHOC: u32 = 0x0000_0002;
const CS_GET_TASK_ALLOW: u32 = 0x0000_0004;
const CS_RUNTIME: u32 = 0x0001_0000;
const CS_LINKER_SIGNED: u32 = 0x0002_0000;
const CS_DEBUGGED: u32 = 0x1000_0000;
const CS_SIGNED: u32 = 0x2000_0000;
const SIG_ADHOC: u32 = 0x0002;
const SIG_RUNTIME: u32 = 0x0001_0000;
const SIG_LINKER_SIGNED: u32 = 0x0002_0000;

pub struct StorageKey(Zeroizing<[u8; 32]>);

impl StorageKey {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(Zeroizing::new(bytes))
    }

    pub fn generate() -> Self {
        let mut bytes = [0u8; 32];
        OsRng.fill_bytes(&mut bytes);
        Self::from_bytes(bytes)
    }

    pub(crate) fn bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Explicit OS key management. No environment variable or plaintext-file fallback.
pub trait KeyProvider {
    fn create(&self, account: &str) -> Result<StorageKey>;
    fn load(&self, account: &str) -> Result<StorageKey>;
}

pub struct PlatformKeychain;

impl KeyProvider for PlatformKeychain {
    fn create(&self, account: &str) -> Result<StorageKey> {
        account_valid(account)?;
        platform::create_key(account)
    }

    fn load(&self, account: &str) -> Result<StorageKey> {
        account_valid(account)?;
        platform::load_key(account)
    }
}

fn account_valid(account: &str) -> Result<()> {
    if account.is_empty()
        || account.len() > 128
        || !account
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
    {
        return Err(Error::Invalid("invalid vault key reference".into()));
    }
    Ok(())
}

struct SigningEvidence {
    cs_flags: u32,
    signature_flags: u32,
    identifier: Option<String>,
    team_id: Option<String>,
    access_groups: Vec<String>,
    /// `None` when the entitlement is absent. `Some(false)` is explicit denial.
    get_task_allow: Option<bool>,
    application_identifier: Option<String>,
}

#[derive(Debug)]
struct EngineScope {
    access_group: String,
    team_id: String,
}

pub(super) struct ProtectionScope<'a> {
    pub service: &'static str,
    pub account: &'a str,
    pub access_group: String,
    pub synchronizable: bool,
    pub data_protection_keychain: bool,
    pub device_only: bool,
}

fn authorize(evidence: &SigningEvidence) -> Result<EngineScope> {
    if evidence.cs_flags & CS_SIGNED == 0 || evidence.cs_flags & CS_VALID == 0 {
        return Err(Error::KeyProvider("engine signature is missing".into()));
    }
    if evidence.cs_flags & (CS_ADHOC | CS_LINKER_SIGNED) != 0
        || evidence.signature_flags & (SIG_ADHOC | SIG_LINKER_SIGNED) != 0
    {
        return Err(Error::KeyProvider("engine signature is ad-hoc".into()));
    }
    if evidence.cs_flags & CS_RUNTIME == 0 || evidence.signature_flags & SIG_RUNTIME == 0 {
        return Err(Error::KeyProvider(
            "engine signature is not hardened".into(),
        ));
    }
    if evidence.cs_flags & CS_DEBUGGED != 0 {
        return Err(Error::KeyProvider("engine is being debugged".into()));
    }
    if evidence.cs_flags & CS_GET_TASK_ALLOW != 0 || evidence.get_task_allow == Some(true) {
        return Err(Error::KeyProvider("engine allows task attach".into()));
    }
    if evidence.identifier.as_deref() != Some(ENGINE_IDENTIFIER) {
        return Err(Error::KeyProvider(
            "engine identifier is not the vault engine".into(),
        ));
    }
    let Some(team) = evidence.team_id.as_deref() else {
        return Err(Error::KeyProvider(
            "engine team identifier is missing".into(),
        ));
    };
    if team.len() != 10
        || !team
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit())
    {
        return Err(Error::KeyProvider(
            "engine team identifier is missing".into(),
        ));
    }
    let access_group = format!("{team}.{VAULT_ACCESS_GROUP_NAME}");
    let application = format!("{team}.{ENGINE_IDENTIFIER}");
    if evidence.access_groups.len() != 1 || evidence.access_groups[0] != access_group {
        return Err(Error::KeyProvider(
            "engine keychain access group is not the signed vault group".into(),
        ));
    }
    if evidence.application_identifier.as_deref() != Some(application.as_str()) {
        return Err(Error::KeyProvider(
            "engine application identifier does not match the signing team".into(),
        ));
    }
    Ok(EngineScope {
        access_group,
        team_id: team.to_string(),
    })
}

pub(super) fn protection_scope<'a>(
    group: &str,
    service: &'static str,
    account: &'a str,
) -> Result<ProtectionScope<'a>> {
    if service != VAULT_SERVICE && service != ANCHOR_SERVICE {
        return Err(Error::Invalid("unknown keychain service".into()));
    }
    if group.is_empty() || !group.contains('.') {
        return Err(Error::KeyProvider(
            "engine keychain access group is not the signed vault group".into(),
        ));
    }
    Ok(ProtectionScope {
        service,
        account,
        access_group: group.to_string(),
        synchronizable: false,
        data_protection_keychain: true,
        device_only: true,
    })
}

pub(super) fn hardened_scope<'a>(
    group: &str,
    service: &'static str,
    account: &'a str,
) -> Result<ProtectionScope<'a>> {
    account_valid(account)?;
    protection_scope(group, service, account)
}

pub(super) fn require_hardened_scope(scope: &ProtectionScope<'_>) -> Result<()> {
    if scope.synchronizable || !scope.data_protection_keychain || !scope.device_only {
        return Err(Error::KeyProvider(
            "keychain scope is not device-local".into(),
        ));
    }
    if scope.access_group.is_empty() {
        return Err(Error::KeyProvider(
            "engine keychain access group is not the signed vault group".into(),
        ));
    }
    Ok(())
}

pub(super) fn reject_duplicate(service: &str) -> Result<()> {
    let message = if service == VAULT_SERVICE {
        "vault key reference already exists"
    } else if service == ANCHOR_SERVICE {
        "checkpoint already exists"
    } else {
        return Err(Error::Invalid("unknown keychain service".into()));
    };
    Err(Error::Conflict(message.into()))
}

fn key_from_secret(mut secret: Zeroizing<Vec<u8>>) -> Result<StorageKey> {
    if secret.len() != 32 {
        return Err(Error::KeyProvider("invalid key length".into()));
    }
    let mut raw = [0u8; 32];
    raw.copy_from_slice(&secret);
    secret.zeroize();
    let key = StorageKey::from_bytes(raw);
    raw.zeroize();
    Ok(key)
}

fn same_bytes(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut difference = 0u8;
    for (left, right) in left.iter().zip(right.iter()) {
        difference |= left ^ right;
    }
    difference == 0
}

#[cfg(target_os = "macos")]
mod platform {
    use std::ptr;
    use std::str::FromStr;

    use core_foundation::array::{
        CFArrayGetCount, CFArrayGetTypeID, CFArrayGetValueAtIndex, CFArrayRef,
    };
    use core_foundation::base::{
        CFGetTypeID, CFRelease, CFType, CFTypeRef, OSStatus, TCFType, ToVoid,
    };
    use core_foundation::boolean::{CFBoolean, CFBooleanRef};
    use core_foundation::data::{CFData, CFDataRef};
    use core_foundation::dictionary::{
        CFDictionaryGetTypeID, CFDictionaryGetValue, CFDictionaryRef, CFMutableDictionary,
    };
    use core_foundation::number::{CFNumber, CFNumberRef};
    use core_foundation::string::{CFString, CFStringRef};
    use security_framework::access_control::{ProtectionMode, SecAccessControl};
    use security_framework::item::{
        update_item, CloudSync, ItemClass, ItemSearchOptions, ItemUpdateOptions, ItemUpdateValue,
        Limit, SearchResult,
    };
    use security_framework::os::macos::code_signing::{Flags, SecCode, SecRequirement};
    use security_framework_sys::base::{errSecDuplicateItem, errSecItemNotFound};
    use security_framework_sys::code_signing::{SecCSFlags, SecStaticCodeRef};
    use security_framework_sys::item::{
        kSecAttrAccessControl, kSecAttrAccessGroup, kSecAttrAccount, kSecAttrService,
        kSecAttrSynchronizable, kSecClass, kSecClassGenericPassword, kSecUseDataProtectionKeychain,
        kSecValueData,
    };
    use security_framework_sys::keychain_item::SecItemAdd;
    use zeroize::Zeroizing;

    use super::anchor::{self, Anchor};
    use super::{
        authorize, hardened_scope, key_from_secret, protection_scope, reject_duplicate,
        require_hardened_scope, same_bytes, EngineScope, ProtectionScope, SigningEvidence,
        StorageKey, ANCHOR_SERVICE, ENGINE_IDENTIFIER, VAULT_SERVICE,
    };
    use crate::{Error, Result};

    #[link(name = "Security", kind = "framework")]
    extern "C" {
        fn SecCodeCopySigningInformation(
            code: SecStaticCodeRef,
            flags: SecCSFlags,
            information: *mut CFDictionaryRef,
        ) -> OSStatus;
        static kSecCodeInfoFlags: CFStringRef;
        static kSecCodeInfoIdentifier: CFStringRef;
        static kSecCodeInfoTeamIdentifier: CFStringRef;
        static kSecCodeInfoEntitlementsDict: CFStringRef;
    }

    extern "C" {
        fn csops(
            pid: libc::pid_t,
            ops: u32,
            useraddr: *mut libc::c_void,
            usersize: libc::size_t,
        ) -> libc::c_int;
    }

    const CS_OPS_STATUS: u32 = 0;
    const SIGNING_AND_DYNAMIC: SecCSFlags = (1 << 1) | (1 << 3);

    pub(super) fn create_key(account: &str) -> Result<StorageKey> {
        let scope = vault_scope(account)?;
        let key = StorageKey::generate();
        add_only(&scope, key.bytes())?;
        match fetch(&scope)? {
            Some(secret) if same_bytes(&secret, key.bytes()) => Ok(key),
            _ => Err(Error::KeyProvider(
                "Keychain access unavailable or refused".into(),
            )),
        }
    }

    pub(super) fn load_key(account: &str) -> Result<StorageKey> {
        let scope = vault_scope(account)?;
        match fetch(&scope)? {
            Some(secret) => key_from_secret(secret),
            None => Err(Error::KeyProvider("vault key is not enrolled".into())),
        }
    }

    pub(super) fn load_anchor(account: &str) -> Result<Option<Anchor>> {
        anchor::resolve_head(&load_history(account)?)
    }

    pub(super) fn advance_anchor(
        account: &str,
        expected: Option<&Anchor>,
        next: &Anchor,
    ) -> Result<()> {
        let logical = account.to_string();
        anchor::publish(
            || load_history(&logical),
            add_authoritative,
            |bytes| write_hint(&logical, bytes),
            expected,
            next,
        )
    }

    fn load_history(logical: &str) -> Result<anchor::History> {
        let group = engine()?.access_group;
        let pairs = list_anchor_items(&group)?;
        Ok(anchor::history_from_pairs(logical, &pairs))
    }

    fn add_authoritative(keychain_account: &str, bytes: &[u8]) -> Result<()> {
        let group = engine()?.access_group;
        let scope = protection_scope(&group, ANCHOR_SERVICE, keychain_account)?;
        anchor::apply_planned(
            &scope,
            anchor::Advance::Insert(bytes.to_vec()),
            |bytes| add_only(&scope, bytes),
            |_| {
                Err(Error::Invalid(
                    "refusing to rewrite a protected checkpoint".into(),
                ))
            },
        )
    }

    fn vault_scope(account: &str) -> Result<ProtectionScope<'_>> {
        hardened_scope(&engine()?.access_group, VAULT_SERVICE, account)
    }

    fn engine() -> Result<EngineScope> {
        let code = SecCode::for_self(Flags::NONE)
            .map_err(|_| Error::KeyProvider("engine signature is unavailable".into()))?;
        let evidence = evidence_from(&code)?;
        let scope = authorize(&evidence)?;
        // Team id is copied from this process's signature. The requirement
        // checks that the leaf OU matches that team. It does not pin a
        // compile-time team or a leaf certificate hash.
        let requirement = format!(
            "identifier \"{ENGINE_IDENTIFIER}\" and anchor apple generic and certificate leaf[subject.OU] = \"{}\"",
            scope.team_id
        );
        let requirement = SecRequirement::from_str(&requirement)
            .map_err(|_| Error::KeyProvider("engine signature is unavailable".into()))?;
        code.check_validity(Flags::NO_NETWORK_ACCESS, &requirement)
            .map_err(|_| Error::KeyProvider("engine signature is not trusted".into()))?;
        Ok(scope)
    }

    fn evidence_from(code: &SecCode) -> Result<SigningEvidence> {
        let mut status = 0u32;
        let rc = unsafe {
            csops(
                libc::getpid(),
                CS_OPS_STATUS,
                &mut status as *mut u32 as *mut libc::c_void,
                std::mem::size_of::<u32>(),
            )
        };
        if rc != 0 {
            return Err(Error::KeyProvider("engine signature is unavailable".into()));
        }
        let mut raw: CFDictionaryRef = ptr::null();
        let copy_status = unsafe {
            SecCodeCopySigningInformation(
                code.as_concrete_TypeRef() as SecStaticCodeRef,
                SIGNING_AND_DYNAMIC,
                &mut raw,
            )
        };
        if copy_status != 0 || raw.is_null() {
            if !raw.is_null() {
                unsafe { CFRelease(raw as CFTypeRef) };
            }
            return Err(Error::KeyProvider("engine signature is unavailable".into()));
        }
        let dict = unsafe { CFType::wrap_under_create_rule(raw as CFTypeRef) };
        parse_evidence(status, dict.as_CFTypeRef())
    }

    fn parse_evidence(cs_flags: u32, raw: CFTypeRef) -> Result<SigningEvidence> {
        if unsafe { CFGetTypeID(raw) } != unsafe { CFDictionaryGetTypeID() } {
            return Err(Error::KeyProvider("engine signature is unavailable".into()));
        }
        let dictionary = raw as CFDictionaryRef;
        let signature_flags = number_field(dictionary, unsafe { kSecCodeInfoFlags })?;
        let entitlements = dictionary_field(dictionary, unsafe { kSecCodeInfoEntitlementsDict })?;
        let (access_groups, get_task_allow, application_identifier) = match entitlements {
            None => (Vec::new(), None, None),
            Some(entitlements) => parse_entitlements(entitlements)?,
        };
        Ok(SigningEvidence {
            cs_flags,
            signature_flags,
            identifier: string_field(dictionary, unsafe { kSecCodeInfoIdentifier })?,
            team_id: string_field(dictionary, unsafe { kSecCodeInfoTeamIdentifier })?,
            access_groups,
            get_task_allow,
            application_identifier,
        })
    }

    fn parse_entitlements(
        dictionary: CFDictionaryRef,
    ) -> Result<(Vec<String>, Option<bool>, Option<String>)> {
        let groups_key = CFString::new("keychain-access-groups");
        let task_key = CFString::new("com.apple.security.get-task-allow");
        let application_key = CFString::new("com.apple.application-identifier");
        let access_groups = match lookup(dictionary, &groups_key)? {
            None => Vec::new(),
            Some(value) => string_array(value)?,
        };
        let get_task_allow = match lookup(dictionary, &task_key)? {
            None => None,
            Some(value) => Some(boolean_value(value)?),
        };
        let application_identifier = match lookup(dictionary, &application_key)? {
            None => None,
            Some(value) => Some(string_value(value)?),
        };
        Ok((access_groups, get_task_allow, application_identifier))
    }

    fn lookup(dictionary: CFDictionaryRef, key: &CFString) -> Result<Option<CFTypeRef>> {
        let value = unsafe { CFDictionaryGetValue(dictionary, key.to_void()) };
        if value.is_null() {
            Ok(None)
        } else {
            Ok(Some(value))
        }
    }

    fn string_field(dictionary: CFDictionaryRef, key: CFStringRef) -> Result<Option<String>> {
        let key = unsafe { CFString::wrap_under_get_rule(key) };
        match lookup(dictionary, &key)? {
            None => Ok(None),
            Some(value) => Ok(Some(string_value(value)?)),
        }
    }

    fn number_field(dictionary: CFDictionaryRef, key: CFStringRef) -> Result<u32> {
        let key = unsafe { CFString::wrap_under_get_rule(key) };
        let Some(value) = lookup(dictionary, &key)? else {
            return Err(Error::KeyProvider("engine signature is unavailable".into()));
        };
        if unsafe { CFGetTypeID(value) } != CFNumber::type_id() {
            return Err(Error::KeyProvider("engine signature is unavailable".into()));
        }
        let number = unsafe { CFNumber::wrap_under_get_rule(value as CFNumberRef) };
        let value = number
            .to_i64()
            .filter(|value| (0..=u32::MAX as i64).contains(value))
            .ok_or_else(|| Error::KeyProvider("engine signature is unavailable".into()))?;
        Ok(value as u32)
    }

    fn dictionary_field(
        dictionary: CFDictionaryRef,
        key: CFStringRef,
    ) -> Result<Option<CFDictionaryRef>> {
        let key = unsafe { CFString::wrap_under_get_rule(key) };
        let Some(value) = lookup(dictionary, &key)? else {
            return Ok(None);
        };
        if unsafe { CFGetTypeID(value) } != unsafe { CFDictionaryGetTypeID() } {
            return Err(Error::KeyProvider(
                "engine entitlements are unreadable".into(),
            ));
        }
        Ok(Some(value as CFDictionaryRef))
    }

    fn string_value(value: CFTypeRef) -> Result<String> {
        if unsafe { CFGetTypeID(value) } != CFString::type_id() {
            return Err(Error::KeyProvider(
                "engine entitlements are unreadable".into(),
            ));
        }
        Ok(unsafe { CFString::wrap_under_get_rule(value as CFStringRef) }.to_string())
    }

    fn boolean_value(value: CFTypeRef) -> Result<bool> {
        if unsafe { CFGetTypeID(value) } != CFBoolean::type_id() {
            return Err(Error::KeyProvider(
                "engine entitlements are unreadable".into(),
            ));
        }
        Ok(bool::from(unsafe {
            CFBoolean::wrap_under_get_rule(value as CFBooleanRef)
        }))
    }

    fn string_array(value: CFTypeRef) -> Result<Vec<String>> {
        if unsafe { CFGetTypeID(value) } != unsafe { CFArrayGetTypeID() } {
            return Err(Error::KeyProvider(
                "engine entitlements are unreadable".into(),
            ));
        }
        let array = value as CFArrayRef;
        let count = unsafe { CFArrayGetCount(array) };
        let mut groups = Vec::with_capacity(count as usize);
        for index in 0..count {
            let element = unsafe { CFArrayGetValueAtIndex(array, index) };
            groups.push(string_value(element)?);
        }
        Ok(groups)
    }

    fn search_options(scope: &ProtectionScope<'_>) -> Result<ItemSearchOptions> {
        require_hardened_scope(scope)?;
        let mut options = ItemSearchOptions::new();
        options
            .class(ItemClass::generic_password())
            .ignore_legacy_keychains()
            .load_data(true)
            .limit(1i64)
            .service(scope.service)
            .account(scope.account)
            .access_group(&scope.access_group)
            .cloud_sync(if scope.synchronizable {
                CloudSync::MatchSyncYes
            } else {
                CloudSync::MatchSyncNo
            });
        Ok(options)
    }

    fn fetch(scope: &ProtectionScope<'_>) -> Result<Option<Zeroizing<Vec<u8>>>> {
        let found = match search_options(scope)?.search() {
            Ok(found) => found,
            Err(error) if error.code() == errSecItemNotFound => return Ok(None),
            Err(_) => {
                return Err(Error::KeyProvider(
                    "Keychain access unavailable or refused".into(),
                ))
            }
        };
        match found.len() {
            0 => Ok(None),
            1 => match found.into_iter().next() {
                Some(SearchResult::Data(bytes)) => Ok(Some(Zeroizing::new(bytes))),
                _ => Err(Error::KeyProvider(
                    "Keychain record has an unexpected shape".into(),
                )),
            },
            _ => Err(Error::KeyProvider(
                "Keychain record has an unexpected shape".into(),
            )),
        }
    }

    fn add_only(scope: &ProtectionScope<'_>, value: &[u8]) -> Result<()> {
        require_hardened_scope(scope)?;
        // ThisDeviceOnly is the SecAccessControl protection class. Adding the
        // legacy accessible attribute as well makes SecItemAdd reject the item.
        let access = SecAccessControl::create_with_protection(
            Some(ProtectionMode::AccessibleWhenUnlockedThisDeviceOnly),
            0,
        )
        .map_err(|_| Error::KeyProvider("cannot create Keychain protection".into()))?;
        let data = CFData::from_buffer(value);
        let service = CFString::new(scope.service);
        let account = CFString::new(scope.account);
        let group = CFString::new(&scope.access_group);
        let mut dict = CFMutableDictionary::from_CFType_pairs(&[]);
        unsafe {
            let class = CFString::wrap_under_get_rule(kSecClassGenericPassword);
            dict.add(&kSecClass.to_void(), &class.to_void());
            dict.add(&kSecAttrService.to_void(), &service.to_void());
            dict.add(&kSecAttrAccount.to_void(), &account.to_void());
            dict.add(&kSecAttrAccessGroup.to_void(), &group.to_void());
            dict.add(
                &kSecAttrSynchronizable.to_void(),
                &CFBoolean::from(scope.synchronizable).to_void(),
            );
            dict.add(
                &kSecUseDataProtectionKeychain.to_void(),
                &CFBoolean::from(scope.data_protection_keychain).to_void(),
            );
            dict.add(&kSecAttrAccessControl.to_void(), &access.to_void());
            dict.add(&kSecValueData.to_void(), &data.to_void());
            let status = SecItemAdd(dict.to_immutable().as_concrete_TypeRef(), ptr::null_mut());
            if status == 0 {
                Ok(())
            } else if status == errSecDuplicateItem {
                // Add-only: a duplicate must not replace the stored secret.
                reject_duplicate(scope.service)
            } else {
                Err(Error::KeyProvider(
                    "Keychain access unavailable or refused".into(),
                ))
            }
        }
    }

    fn list_anchor_items(group: &str) -> Result<Vec<(String, Vec<u8>)>> {
        if group.is_empty() || !group.contains('.') {
            return Err(Error::KeyProvider(
                "engine keychain access group is not the signed vault group".into(),
            ));
        }
        let mut options = ItemSearchOptions::new();
        options
            .class(ItemClass::generic_password())
            .ignore_legacy_keychains()
            .load_attributes(true)
            .load_data(true)
            .limit(Limit::All)
            .service(ANCHOR_SERVICE)
            .access_group(group)
            .cloud_sync(CloudSync::MatchSyncNo);
        let found = match options.search() {
            Ok(found) => found,
            Err(error) if error.code() == errSecItemNotFound => return Ok(Vec::new()),
            Err(_) => {
                return Err(Error::KeyProvider(
                    "Keychain access unavailable or refused".into(),
                ))
            }
        };
        let mut items = Vec::with_capacity(found.len());
        for item in found {
            let SearchResult::Dict(dict) = item else {
                return Err(Error::KeyProvider(
                    "Keychain record has an unexpected shape".into(),
                ));
            };
            let (account, secret) = account_and_secret(dict.as_concrete_TypeRef())?;
            items.push((account, secret.to_vec()));
        }
        Ok(items)
    }

    fn account_and_secret(dictionary: CFDictionaryRef) -> Result<(String, Zeroizing<Vec<u8>>)> {
        let account_key = unsafe { CFString::wrap_under_get_rule(kSecAttrAccount) };
        let data_key = unsafe { CFString::wrap_under_get_rule(kSecValueData) };
        let account = match lookup(dictionary, &account_key)? {
            Some(value) => string_value(value)?,
            None => {
                return Err(Error::KeyProvider(
                    "Keychain record has an unexpected shape".into(),
                ))
            }
        };
        let Some(value) = lookup(dictionary, &data_key)? else {
            return Err(Error::KeyProvider(
                "Keychain record has an unexpected shape".into(),
            ));
        };
        if unsafe { CFGetTypeID(value) } != CFData::type_id() {
            return Err(Error::KeyProvider(
                "Keychain record has an unexpected shape".into(),
            ));
        }
        let data = unsafe { CFData::wrap_under_get_rule(value as CFDataRef) };
        Ok((account, Zeroizing::new(data.bytes().to_vec())))
    }

    fn write_hint(logical: &str, value: &[u8]) -> Result<()> {
        let group = engine()?.access_group;
        let account = anchor::hint_account(logical);
        let scope = protection_scope(&group, ANCHOR_SERVICE, &account)?;
        require_hardened_scope(&scope)?;
        if scope.account != account || scope.service != ANCHOR_SERVICE {
            return Err(Error::Invalid(
                "refusing to rewrite a protected checkpoint".into(),
            ));
        }
        match fetch(&scope)? {
            Some(_) => update_hint(&scope, value),
            None => match add_only(&scope, value) {
                Ok(()) => Ok(()),
                Err(error) if anchor::is_duplicate(&error) => update_hint(&scope, value),
                Err(error) => Err(error),
            },
        }
    }

    fn update_hint(scope: &ProtectionScope<'_>, value: &[u8]) -> Result<()> {
        if scope.service != ANCHOR_SERVICE || !scope.account.starts_with("h1:") {
            return Err(Error::Invalid(
                "refusing to rewrite a protected checkpoint".into(),
            ));
        }
        anchor::apply_planned(
            scope,
            anchor::Advance::Hint(value.to_vec()),
            |_| {
                Err(Error::Invalid(
                    "refusing to rewrite a protected checkpoint".into(),
                ))
            },
            |bytes| {
                let data = CFData::from_buffer(bytes);
                let mut update = ItemUpdateOptions::new();
                update.set_value(ItemUpdateValue::Data(data));
                match update_item(&search_options(scope)?, &update) {
                    Ok(()) => Ok(()),
                    Err(error) if error.code() == errSecItemNotFound => {
                        Err(Error::Conflict("checkpoint is missing".into()))
                    }
                    Err(_) => Err(Error::KeyProvider(
                        "Keychain access unavailable or refused".into(),
                    )),
                }
            },
        )
    }
}

#[cfg(not(target_os = "macos"))]
mod platform {
    use super::anchor::Anchor;
    use super::StorageKey;
    use crate::{Error, Result};

    fn unsupported() -> Error {
        Error::KeyProvider("no platform key provider configured".into())
    }

    pub(super) fn create_key(_account: &str) -> Result<StorageKey> {
        Err(unsupported())
    }

    pub(super) fn load_key(_account: &str) -> Result<StorageKey> {
        Err(unsupported())
    }

    pub(super) fn load_anchor(_account: &str) -> Result<Option<Anchor>> {
        Err(unsupported())
    }

    pub(super) fn advance_anchor(
        _account: &str,
        _expected: Option<&Anchor>,
        _next: &Anchor,
    ) -> Result<()> {
        Err(unsupported())
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::sync::Mutex;

    use super::anchor::{self, Advance, Anchor, AnchorStore};
    use super::{
        account_valid, authorize, hardened_scope, protection_scope, reject_duplicate,
        require_hardened_scope, EngineScope, KeyProvider, ProtectionScope, SigningEvidence,
        StorageKey, ANCHOR_SERVICE, CS_ADHOC, CS_DEBUGGED, CS_GET_TASK_ALLOW, CS_LINKER_SIGNED,
        CS_RUNTIME, CS_SIGNED, CS_VALID, ENGINE_IDENTIFIER, SIG_ADHOC, SIG_LINKER_SIGNED,
        SIG_RUNTIME, VAULT_SERVICE,
    };
    use crate::Error;

    fn valid_evidence() -> SigningEvidence {
        SigningEvidence {
            cs_flags: CS_VALID | CS_SIGNED | CS_RUNTIME,
            signature_flags: SIG_RUNTIME,
            identifier: Some(ENGINE_IDENTIFIER.to_string()),
            team_id: Some("ABCDE12345".to_string()),
            access_groups: vec!["ABCDE12345.com.agent-yhes.engine.vault".to_string()],
            get_task_allow: None,
            application_identifier: Some("ABCDE12345.com.agent-yhes.engine".to_string()),
        }
    }

    fn scope_of(evidence: &SigningEvidence) -> EngineScope {
        authorize(evidence).expect("valid evidence")
    }

    #[test]
    fn identity_gate_accepts_hardened_engine_and_rejects_the_rest() {
        let accepted = scope_of(&valid_evidence());
        assert_eq!(
            accepted.access_group,
            "ABCDE12345.com.agent-yhes.engine.vault"
        );
        let mut explicit_false = valid_evidence();
        explicit_false.get_task_allow = Some(false);
        assert!(authorize(&explicit_false).is_ok());

        let cases = [
            (
                "unsigned",
                {
                    let mut evidence = valid_evidence();
                    evidence.cs_flags &= !CS_SIGNED;
                    evidence
                },
                "signature is missing",
            ),
            (
                "adhoc-status",
                {
                    let mut evidence = valid_evidence();
                    evidence.cs_flags |= CS_ADHOC;
                    evidence
                },
                "ad-hoc",
            ),
            (
                "linker-signature",
                {
                    let mut evidence = valid_evidence();
                    evidence.signature_flags |= SIG_LINKER_SIGNED;
                    evidence
                },
                "ad-hoc",
            ),
            (
                "linker-status",
                {
                    let mut evidence = valid_evidence();
                    evidence.cs_flags |= CS_LINKER_SIGNED;
                    evidence
                },
                "ad-hoc",
            ),
            (
                "static-adhoc",
                {
                    let mut evidence = valid_evidence();
                    evidence.signature_flags |= SIG_ADHOC;
                    evidence
                },
                "ad-hoc",
            ),
            (
                "not-hardened",
                {
                    let mut evidence = valid_evidence();
                    evidence.cs_flags &= !CS_RUNTIME;
                    evidence
                },
                "not hardened",
            ),
            (
                "task-allow",
                {
                    let mut evidence = valid_evidence();
                    evidence.cs_flags |= CS_GET_TASK_ALLOW;
                    evidence
                },
                "task attach",
            ),
            (
                "task-entitlement",
                {
                    let mut evidence = valid_evidence();
                    evidence.get_task_allow = Some(true);
                    evidence
                },
                "task attach",
            ),
            (
                "debugged",
                {
                    let mut evidence = valid_evidence();
                    evidence.cs_flags |= CS_DEBUGGED;
                    evidence
                },
                "being debugged",
            ),
            (
                "wrong-identifier",
                {
                    let mut evidence = valid_evidence();
                    evidence.identifier = Some("com.example.other".to_string());
                    evidence
                },
                "identifier",
            ),
            (
                "missing-team",
                {
                    let mut evidence = valid_evidence();
                    evidence.team_id = None;
                    evidence
                },
                "team identifier",
            ),
            (
                "extra-group",
                {
                    let mut evidence = valid_evidence();
                    evidence
                        .access_groups
                        .push("ABCDE12345.com.agent-yhes.engine".to_string());
                    evidence
                },
                "access group",
            ),
            (
                "wrong-application",
                {
                    let mut evidence = valid_evidence();
                    evidence.application_identifier = Some("ABCDE12345.com.example".to_string());
                    evidence
                },
                "application identifier",
            ),
        ];
        for (name, evidence, needle) in cases {
            let message = authorize(&evidence).expect_err(name).to_string();
            assert!(message.contains(needle), "{name}: {message}");
        }
    }

    #[test]
    fn vault_and_anchor_queries_share_one_device_local_scope() {
        let group = scope_of(&valid_evidence()).access_group;
        let vault = hardened_scope(&group, VAULT_SERVICE, "project_a").unwrap();
        let anchor = hardened_scope(&group, ANCHOR_SERVICE, "project_a").unwrap();
        assert_eq!(vault.access_group, anchor.access_group);
        assert!(!vault.synchronizable && !anchor.synchronizable);
        assert!(vault.data_protection_keychain && anchor.data_protection_keychain);
        assert!(vault.device_only && anchor.device_only);
        assert_ne!(vault.service, anchor.service);
        let mut widened = vault;
        widened.synchronizable = true;
        assert!(require_hardened_scope(&widened).is_err());
        assert!(account_valid("").is_err());
        assert!(account_valid("../x").is_err());
    }

    #[test]
    fn duplicate_key_add_conflicts_and_checkpoint_write_skips_vault_service() {
        assert!(reject_duplicate(VAULT_SERVICE)
            .unwrap_err()
            .to_string()
            .contains("already exists"));
        let group = scope_of(&valid_evidence()).access_group;
        let scope = hardened_scope(&group, VAULT_SERVICE, "acct").unwrap();
        let planned = Advance::Insert(b"next".to_vec());
        let error =
            anchor::apply_planned(&scope, planned, |_| panic!("insert"), |_| panic!("hint"))
                .expect_err("vault service");
        assert!(error.to_string().contains("vault key"));
        let revision_account = anchor::revision_account("acct", 1);
        let hint_account = anchor::hint_account("acct");
        let revision = protection_scope(&group, ANCHOR_SERVICE, &revision_account).unwrap();
        let hint = protection_scope(&group, ANCHOR_SERVICE, &hint_account).unwrap();
        assert!(anchor::apply_planned(
            &revision,
            Advance::Hint(b"hint".to_vec()),
            |_| panic!("insert"),
            |_| panic!("hint"),
        )
        .is_err());
        assert!(anchor::apply_planned(
            &hint,
            Advance::Insert(b"record".to_vec()),
            |_| panic!("insert"),
            |_| panic!("hint"),
        )
        .is_err());
    }

    type ItemMap = BTreeMap<(String, String, String), Vec<Vec<u8>>>;
    type AddHook = Box<dyn FnOnce(&mut ItemMap)>;

    struct FakeStore {
        group: String,
        items: Mutex<ItemMap>,
        before_add: Mutex<Option<AddHook>>,
        fail_hints: Mutex<bool>,
    }

    impl FakeStore {
        fn new(group: &str) -> Self {
            Self {
                group: group.to_string(),
                items: Mutex::new(BTreeMap::new()),
                before_add: Mutex::new(None),
                fail_hints: Mutex::new(false),
            }
        }

        fn scope<'a>(
            &self,
            service: &'static str,
            account: &'a str,
        ) -> crate::Result<ProtectionScope<'a>> {
            let scope = hardened_scope(&self.group, service, account)?;
            require_hardened_scope(&scope)?;
            Ok(scope)
        }

        fn slot(scope: &ProtectionScope<'_>) -> (String, String, String) {
            (
                scope.access_group.clone(),
                scope.service.to_string(),
                scope.account.to_string(),
            )
        }

        fn history(&self, logical: &str) -> crate::Result<anchor::History> {
            account_valid(logical)?;
            let items = self.items.lock().expect("test lock");
            let mut pairs = Vec::new();
            for ((group, service, account), payloads) in items.iter() {
                if group == &self.group && service == ANCHOR_SERVICE {
                    for payload in payloads {
                        pairs.push((account.clone(), payload.clone()));
                    }
                }
            }
            Ok(anchor::history_from_pairs(logical, &pairs))
        }

        fn add_authoritative(&self, keychain_account: &str, bytes: &[u8]) -> crate::Result<()> {
            let scope = protection_scope(&self.group, ANCHOR_SERVICE, keychain_account)?;
            require_hardened_scope(&scope)?;
            anchor::apply_planned(
                &scope,
                Advance::Insert(bytes.to_vec()),
                |bytes| {
                    let mut items = self.items.lock().expect("test lock");
                    if let Some(hook) = self.before_add.lock().expect("hook").take() {
                        hook(&mut items);
                    }
                    let entry = items.entry(Self::slot(&scope)).or_default();
                    if !entry.is_empty() {
                        return Err(duplicate_error(ANCHOR_SERVICE));
                    }
                    entry.push(bytes.to_vec());
                    Ok(())
                },
                |_| unreachable!("add-only publication does not update"),
            )
        }

        fn write_hint(&self, logical: &str, bytes: &[u8]) -> crate::Result<()> {
            if *self.fail_hints.lock().expect("hint flag") {
                return Err(Error::KeyProvider("hint unavailable".into()));
            }
            let account = anchor::hint_account(logical);
            let scope = protection_scope(&self.group, ANCHOR_SERVICE, &account)?;
            require_hardened_scope(&scope)?;
            anchor::apply_planned(
                &scope,
                Advance::Hint(bytes.to_vec()),
                |_| unreachable!("hint publication is not an insert"),
                |bytes| {
                    let mut items = self.items.lock().expect("test lock");
                    items.insert(Self::slot(&scope), vec![bytes.to_vec()]);
                    Ok(())
                },
            )
        }

        fn plant(&self, keychain_account: &str, bytes: &[u8]) {
            let mut items = self.items.lock().expect("test lock");
            items
                .entry((
                    self.group.clone(),
                    ANCHOR_SERVICE.to_string(),
                    keychain_account.to_string(),
                ))
                .or_default()
                .push(bytes.to_vec());
        }

        fn payloads(&self, keychain_account: &str) -> Vec<Vec<u8>> {
            self.items
                .lock()
                .expect("test lock")
                .get(&(
                    self.group.clone(),
                    ANCHOR_SERVICE.to_string(),
                    keychain_account.to_string(),
                ))
                .cloned()
                .unwrap_or_default()
        }

        fn vault_payloads(&self, account: &str) -> Vec<Vec<u8>> {
            let scope = self.scope(VAULT_SERVICE, account).expect("vault scope");
            self.items
                .lock()
                .expect("test lock")
                .get(&Self::slot(&scope))
                .cloned()
                .unwrap_or_default()
        }
    }

    impl KeyProvider for FakeStore {
        fn create(&self, account: &str) -> crate::Result<StorageKey> {
            let scope = self.scope(VAULT_SERVICE, account)?;
            let key = StorageKey::generate();
            let mut items = self.items.lock().expect("test lock");
            let slot = Self::slot(&scope);
            let entry = items.entry(slot).or_default();
            if !entry.is_empty() {
                return Err(duplicate_error(VAULT_SERVICE));
            }
            entry.push(key.bytes().to_vec());
            Ok(key)
        }

        fn load(&self, account: &str) -> crate::Result<StorageKey> {
            let scope = self.scope(VAULT_SERVICE, account)?;
            let items = self.items.lock().expect("test lock");
            let Some(payloads) = items.get(&Self::slot(&scope)) else {
                return Err(Error::KeyProvider("vault key is not enrolled".into()));
            };
            if payloads.len() != 1 || payloads[0].len() != 32 {
                return Err(Error::KeyProvider("invalid key length".into()));
            }
            let mut raw = [0u8; 32];
            raw.copy_from_slice(&payloads[0]);
            Ok(StorageKey::from_bytes(raw))
        }
    }

    impl AnchorStore for FakeStore {
        fn load(&self, account: &str) -> crate::Result<Option<Anchor>> {
            anchor::resolve_head(&self.history(account)?)
        }

        fn advance(
            &self,
            account: &str,
            expected: Option<&Anchor>,
            next: &Anchor,
        ) -> crate::Result<()> {
            let logical = account.to_string();
            anchor::publish(
                || self.history(&logical),
                |keychain_account, bytes| self.add_authoritative(keychain_account, bytes),
                |bytes| self.write_hint(&logical, bytes),
                expected,
                next,
            )
        }
    }

    fn duplicate_error(service: &str) -> Error {
        match reject_duplicate(service) {
            Err(error) => error,
            Ok(()) => unreachable!("duplicate rejection is a conflict"),
        }
    }

    fn digest(seed: u8) -> String {
        format!("{seed:02x}").repeat(32)
    }

    #[test]
    fn fake_store_keeps_keys_immutable_and_checkpoints_compare_and_set() {
        let group = scope_of(&valid_evidence()).access_group;
        let store = FakeStore::new(&group);
        let other = FakeStore::new("ZZZZZZZZZZ.com.agent-yhes.engine.vault");
        let created = store.create("project_a").unwrap();
        let vault_before = store.vault_payloads("project_a");
        assert!(store.create("project_a").is_err());
        assert_eq!(
            KeyProvider::load(&store, "project_a").unwrap().bytes(),
            created.bytes()
        );
        assert!(KeyProvider::load(&other, "project_a").is_err());
        assert!(KeyProvider::load(&store, "missing").is_err());

        let first = Anchor {
            revision: 1,
            digest: digest(1),
        };
        let second = Anchor {
            revision: 2,
            digest: digest(2),
        };
        assert!(AnchorStore::load(&store, "project_a").unwrap().is_none());
        store.advance("project_a", None, &first).unwrap();
        assert_eq!(
            AnchorStore::load(&store, "project_a").unwrap().as_ref(),
            Some(&first)
        );
        assert!(store.advance("project_a", None, &second).is_err());
        assert_eq!(
            AnchorStore::load(&store, "project_a").unwrap().as_ref(),
            Some(&first)
        );
        let wrong = Anchor {
            revision: 9,
            digest: digest(9),
        };
        assert!(store.advance("project_a", Some(&wrong), &second).is_err());
        assert_eq!(
            AnchorStore::load(&store, "project_a").unwrap().as_ref(),
            Some(&first)
        );
        store.advance("project_a", Some(&first), &second).unwrap();
        store.advance("project_a", Some(&first), &second).unwrap();
        assert_eq!(
            AnchorStore::load(&store, "project_a").unwrap().as_ref(),
            Some(&second)
        );
        let other_digest = Anchor {
            revision: 2,
            digest: digest(3),
        };
        assert!(store
            .advance("project_a", Some(&first), &other_digest)
            .is_err());
        assert_eq!(
            AnchorStore::load(&store, "project_a").unwrap().as_ref(),
            Some(&second)
        );
        assert_eq!(
            store
                .payloads(&anchor::revision_account("project_a", 2))
                .len(),
            1
        );
        assert_eq!(
            store.payloads(&anchor::genesis_account("project_a")).len(),
            1
        );
        store.advance("pro", None, &first).unwrap();
        store.advance("proj", None, &second).unwrap();
        assert_eq!(
            AnchorStore::load(&store, "pro").unwrap().as_ref(),
            Some(&first)
        );
        assert_eq!(
            AnchorStore::load(&store, "proj").unwrap().as_ref(),
            Some(&second)
        );
        assert!(store.create("project_a").is_err());
        assert_eq!(
            KeyProvider::load(&store, "project_a").unwrap().bytes(),
            created.bytes()
        );
        assert_eq!(store.vault_payloads("project_a"), vault_before);
    }

    #[test]
    fn checkpoint_codec_rejects_secrets_and_loose_text() {
        let anchor = Anchor {
            revision: 0,
            digest: digest(4),
        };
        let bytes = anchor::encode_anchor(&anchor).unwrap();
        assert_eq!(anchor::decode_anchor(&bytes).unwrap(), anchor);
        assert!(anchor::decode_anchor(&[7u8; 32]).is_err());
        assert!(anchor::encode_anchor(&Anchor {
            revision: 1,
            digest: "AA".repeat(32),
        })
        .is_err());
        let mut corrupt = bytes.clone();
        corrupt.extend_from_slice(b"\n");
        assert!(anchor::decode_anchor(&corrupt).is_err());
        let record = anchor::encode_record(None, &anchor).unwrap();
        assert_eq!(
            anchor::decode_record(&record).unwrap(),
            (None, anchor.clone())
        );
        assert!(anchor::encode_record(
            Some(&anchor),
            &Anchor {
                revision: 2,
                digest: digest(5),
            },
        )
        .is_err());
        let group = scope_of(&valid_evidence()).access_group;
        let store = FakeStore::new(&group);
        store.plant("broken", b"not-a-checkpoint");
        assert!(AnchorStore::load(&store, "broken").is_err());
        assert!(store
            .advance(
                "broken",
                Some(&anchor),
                &Anchor {
                    revision: 1,
                    digest: digest(5)
                }
            )
            .is_err());
        assert_eq!(store.payloads("broken"), vec![b"not-a-checkpoint".to_vec()]);
        assert!(store
            .payloads(&anchor::genesis_account("broken"))
            .is_empty());
    }

    #[test]
    fn race_winner_keeps_its_digest_and_loser_conflicts() {
        let group = scope_of(&valid_evidence()).access_group;
        let store = FakeStore::new(&group);
        let winner = Anchor {
            revision: 4,
            digest: digest(4),
        };
        let winner_bytes = anchor::encode_record(None, &winner).unwrap();
        let account = anchor::genesis_account("project_a");
        let planted_group = group.clone();
        let planted_account = account.clone();
        let planted_bytes = winner_bytes.clone();
        store
            .before_add
            .lock()
            .unwrap()
            .replace(Box::new(move |items| {
                items
                    .entry((planted_group, ANCHOR_SERVICE.to_string(), planted_account))
                    .or_default()
                    .push(planted_bytes);
            }));
        let loser = Anchor {
            revision: 9,
            digest: digest(9),
        };
        assert!(store.advance("project_a", None, &loser).is_err());
        assert_eq!(
            AnchorStore::load(&store, "project_a").unwrap().as_ref(),
            Some(&winner)
        );
        store.advance("project_a", None, &winner).unwrap();
        assert!(store.advance("project_a", None, &loser).is_err());
        assert_eq!(store.payloads(&account), vec![winner_bytes]);

        let genesis = Anchor {
            revision: 0,
            digest: digest(1),
        };
        store.advance("race", None, &genesis).unwrap();
        let kept = Anchor {
            revision: 1,
            digest: digest(2),
        };
        let rejected = Anchor {
            revision: 1,
            digest: digest(3),
        };
        let kept_bytes = anchor::encode_record(Some(&genesis), &kept).unwrap();
        let revision = anchor::revision_account("race", 1);
        let planted_group = group.clone();
        let planted_revision = revision.clone();
        let planted_bytes = kept_bytes.clone();
        store
            .before_add
            .lock()
            .unwrap()
            .replace(Box::new(move |items| {
                items
                    .entry((planted_group, ANCHOR_SERVICE.to_string(), planted_revision))
                    .or_default()
                    .push(planted_bytes);
            }));
        assert!(store.advance("race", Some(&genesis), &rejected).is_err());
        assert_eq!(
            AnchorStore::load(&store, "race").unwrap().as_ref(),
            Some(&kept)
        );
        store.advance("race", Some(&genesis), &kept).unwrap();
        assert!(store.advance("race", Some(&genesis), &rejected).is_err());
        assert_eq!(store.payloads(&revision), vec![kept_bytes]);
        assert_eq!(store.payloads(&anchor::genesis_account("race")).len(), 1);
    }

    #[test]
    fn lost_or_lying_head_hint_is_not_authority() {
        let group = scope_of(&valid_evidence()).access_group;
        let store = FakeStore::new(&group);
        let genesis = Anchor {
            revision: 0,
            digest: digest(1),
        };
        let next = Anchor {
            revision: 1,
            digest: digest(2),
        };
        let lie = Anchor {
            revision: 7,
            digest: digest(7),
        };
        store.plant(
            &anchor::hint_account("empty"),
            &anchor::encode_record(None, &lie).unwrap(),
        );
        assert!(AnchorStore::load(&store, "empty").unwrap().is_none());
        store.advance("empty", None, &genesis).unwrap();
        assert_eq!(
            AnchorStore::load(&store, "empty").unwrap().as_ref(),
            Some(&genesis)
        );

        store.advance("project_a", None, &genesis).unwrap();
        store.advance("project_a", Some(&genesis), &next).unwrap();
        let hint = anchor::hint_account("project_a");
        store.items.lock().unwrap().remove(&(
            group.clone(),
            ANCHOR_SERVICE.to_string(),
            hint.clone(),
        ));
        store.plant(&hint, &anchor::encode_record(None, &lie).unwrap());
        assert_eq!(
            AnchorStore::load(&store, "project_a").unwrap().as_ref(),
            Some(&next)
        );
        *store.fail_hints.lock().unwrap() = true;
        let third = Anchor {
            revision: 2,
            digest: digest(3),
        };
        store.advance("project_a", Some(&next), &third).unwrap();
        assert_eq!(
            AnchorStore::load(&store, "project_a").unwrap().as_ref(),
            Some(&third)
        );
        assert_eq!(
            anchor::decode_record(&store.payloads(&hint)[0]).unwrap().1,
            lie
        );
        store
            .items
            .lock()
            .unwrap()
            .remove(&(group, ANCHOR_SERVICE.to_string(), hint));
        assert_eq!(
            AnchorStore::load(&store, "project_a").unwrap().as_ref(),
            Some(&third)
        );
    }

    #[test]
    fn gaps_and_forks_fail_closed_and_history_is_kept() {
        let group = scope_of(&valid_evidence()).access_group;
        let store = FakeStore::new(&group);
        let genesis = Anchor {
            revision: 0,
            digest: digest(1),
        };
        let missing = Anchor {
            revision: 1,
            digest: digest(2),
        };
        let skipped = Anchor {
            revision: 2,
            digest: digest(3),
        };
        store.plant(
            &anchor::genesis_account("gap"),
            &anchor::encode_record(None, &genesis).unwrap(),
        );
        store.plant(
            &anchor::revision_account("gap", 2),
            &anchor::encode_record(Some(&missing), &skipped).unwrap(),
        );
        let gap_before = (
            store.payloads(&anchor::genesis_account("gap")),
            store.payloads(&anchor::revision_account("gap", 2)),
        );
        assert!(AnchorStore::load(&store, "gap").is_err());
        assert!(store
            .advance(
                "gap",
                Some(&genesis),
                &Anchor {
                    revision: 1,
                    digest: digest(4),
                },
            )
            .is_err());
        assert_eq!(
            (
                store.payloads(&anchor::genesis_account("gap")),
                store.payloads(&anchor::revision_account("gap", 2)),
            ),
            gap_before
        );

        store.advance("fork", None, &genesis).unwrap();
        let left = Anchor {
            revision: 1,
            digest: digest(5),
        };
        let right = Anchor {
            revision: 1,
            digest: digest(6),
        };
        store.plant(
            &anchor::revision_account("fork", 1),
            &anchor::encode_record(Some(&genesis), &left).unwrap(),
        );
        store.plant(
            &anchor::revision_account("fork", 1),
            &anchor::encode_record(Some(&genesis), &right).unwrap(),
        );
        let forked = store.payloads(&anchor::revision_account("fork", 1));
        assert_eq!(forked.len(), 2);
        assert!(AnchorStore::load(&store, "fork").is_err());
        assert!(store.advance("fork", Some(&genesis), &left).is_err());
        assert_eq!(store.payloads(&anchor::revision_account("fork", 1)), forked);

        store.plant(
            &anchor::genesis_account("double"),
            &anchor::encode_record(None, &left).unwrap(),
        );
        store.plant(
            &anchor::genesis_account("double"),
            &anchor::encode_record(None, &right).unwrap(),
        );
        let doubled = store.payloads(&anchor::genesis_account("double"));
        assert!(AnchorStore::load(&store, "double").is_err());
        assert!(store.advance("double", None, &left).is_err());
        assert_eq!(store.payloads(&anchor::genesis_account("double")), doubled);

        let legacy = anchor::encode_anchor(&Anchor {
            revision: 3,
            digest: digest(8),
        })
        .unwrap();
        store.plant("legacy", &legacy);
        assert!(AnchorStore::load(&store, "legacy").is_err());
        assert!(store
            .advance(
                "legacy",
                None,
                &Anchor {
                    revision: 0,
                    digest: digest(9),
                },
            )
            .is_err());
        assert_eq!(store.payloads("legacy"), vec![legacy]);
        assert!(store
            .payloads(&anchor::genesis_account("legacy"))
            .is_empty());
    }
}
