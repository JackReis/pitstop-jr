import Foundation

/// Keychain access via the `/usr/bin/security` CLI — the same path Claude
/// Code itself uses (its binary shells out to find-/add-generic-password).
///
/// Why the CLI instead of the SecItem API: keychain ACL grants are per
/// requesting binary. PitStop is ad-hoc signed, so every rebuild used to
/// invalidate its grant and re-prompt; and Claude Code's own accesses prompt
/// as "security". Routing through `security` means ONE stable, Apple-signed
/// requester for both apps — a single "Always Allow" (with the keychain
/// password entered) persists across PitStop rebuilds and Claude Code logins.
///
/// Trade-off: `add-generic-password` passes the secret via argv, which is
/// momentarily visible in the process list. Claude Code has the same
/// exposure; on a single-user machine this is acceptable.
///
/// Two services are involved:
///  - "Claude Code-credentials" — the live item Claude Code reads/writes.
///    Always updated in place (`-U`) to preserve the item and its ACL.
///  - "PitStop-profile" — one item per saved account (account = email).
///    Recreated (staged add + delete + add) on write so the items are owned
///    by `security` itself and never prompt, without a window where a failed
///    write has destroyed the only copy.
///
/// All calls are async: `security` blocks until any keychain authorization
/// prompt is answered, so it must never run on the main thread.
enum Keychain {
    struct Failure: LocalizedError {
        let message: String
        var errorDescription: String? { message }
    }

    private static let tool = "/usr/bin/security"

    @discardableResult
    private static func run(_ args: [String]) async throws -> (status: Int32, out: Data, err: String) {
        try await withCheckedThrowingContinuation { cont in
            DispatchQueue.global(qos: .userInitiated).async {
                let p = Process()
                p.executableURL = URL(fileURLWithPath: tool)
                p.arguments = args
                let outPipe = Pipe()
                let errPipe = Pipe()
                p.standardOutput = outPipe
                p.standardError = errPipe
                do {
                    try p.run()
                } catch {
                    cont.resume(throwing: Failure(message: "Couldn't run security: \(error.localizedDescription)"))
                    return
                }
                // Drain both pipes concurrently — a sequential read-to-end
                // deadlocks if the child fills the other pipe's buffer.
                var out = Data(), err = Data()
                let drained = DispatchGroup()
                drained.enter()
                DispatchQueue.global(qos: .utility).async {
                    out = outPipe.fileHandleForReading.readDataToEndOfFile(); drained.leave()
                }
                drained.enter()
                DispatchQueue.global(qos: .utility).async {
                    err = errPipe.fileHandleForReading.readDataToEndOfFile(); drained.leave()
                }
                p.waitUntilExit()
                drained.wait()
                cont.resume(returning: (p.terminationStatus, out, String(data: err, encoding: .utf8) ?? ""))
            }
        }
    }

    /// `security` exits 44 when no matching item exists.
    private static let notFound: Int32 = 44

    /// Read a generic password. When `account` is nil (the live Claude Code
    /// credential lookup), prefer the item keyed by `NSUserName()` — matching
    /// Claude Code's own `find-generic-password -a $USER -s ...` — and only
    /// fall back to an unscoped service match if no per-user item exists. A
    /// daemon invocation of Claude Code without `$USER` in its environment
    /// writes a separate item under `"unknown"` or `"claude-code-user"`; if
    /// that item was created earlier, an unscoped `-s` lookup returns the
    /// stale daemon item instead of the user's live session.
    ///
    /// When a specific account is missing, falls back to (and promotes) its
    /// staging sibling — a crash between upsert's delete and add can leave the
    /// only copy there.
    static func read(service: String, account: String? = nil) async throws -> Data? {
        try await read(
            service: service,
            account: account,
            user: NSUserName(),
            fetch: { try await readRaw(service: service, account: $0) },
            promote: { stagedAccount, value in
                let r = try? await run(["add-generic-password", "-s", service, "-a", stagedAccount, "-w", value])
                if r?.status == 0 {
                    _ = try? await run(["delete-generic-password", "-s", service,
                                        "-a", stagingAccount(for: stagedAccount)])
                }
            })
    }

    static func read(
        service: String,
        account: String?,
        user: String,
        fetch: (String?) async throws -> Data?,
        promote: (String, String) async -> Void = { _, _ in }
    ) async throws -> Data? {
        guard let account else {
            if let data = try await fetch(user) { return data }
            return try await fetch(nil)
        }
        if let data = try await fetch(account) { return data }
        guard let staged = try? await fetch(stagingAccount(for: account)),
              let value = String(data: staged, encoding: .utf8) else { return nil }
        // Promote the stranded copy back to the real item (best-effort).
        await promote(account, value)
        return staged
    }

    private static func readRaw(service: String, account: String?) async throws -> Data? {
        var args = ["find-generic-password", "-s", service]
        if let account { args += ["-a", account] }
        args.append("-w")
        let r = try await run(args)
        if r.status == notFound { return nil }
        guard r.status == 0 else {
            throw Failure(message: "Keychain read of \(service) failed (\(r.status)): "
                + r.err.trimmingCharacters(in: .whitespacesAndNewlines))
        }
        var data = r.out
        if data.last == 0x0A { data.removeLast() }   // `-w` appends a newline
        return dehexed(data)
    }

    /// `security find-generic-password -w` prints a value hex-encoded when it
    /// contains bytes outside plain printable ASCII (e.g. the newlines of a
    /// pretty-printed JSON blob stored before PitStop normalized blobs).
    /// Decode only when the raw value isn't itself a credential shape but the
    /// hex-decoded bytes are — so a real secret that merely looks hexy is safe.
    static func dehexed(_ data: Data) -> Data {
        guard data.count >= 2, data.count % 2 == 0,
              !looksLikeCredential(data),
              let text = String(data: data, encoding: .utf8),
              text.allSatisfy(\.isHexDigit) else { return data }
        var bytes = [UInt8](); bytes.reserveCapacity(data.count / 2)
        var idx = text.startIndex
        while idx < text.endIndex {
            let next = text.index(idx, offsetBy: 2)
            guard let b = UInt8(text[idx..<next], radix: 16) else { return data }
            bytes.append(b)
            idx = next
        }
        let decoded = Data(bytes)
        return looksLikeCredential(decoded) ? decoded : data
    }

    private static func looksLikeCredential(_ data: Data) -> Bool {
        if (try? JSONSerialization.jsonObject(with: data)) != nil { return true }
        guard let s = String(data: data, encoding: .utf8) else { return false }
        return s.trimmingCharacters(in: .whitespacesAndNewlines).hasPrefix("go-keyring-base64:")
    }

    /// Write a profile item. Delete + add (rather than `-U`) so the item ends
    /// up created by `security` itself — silent access forever after. The new
    /// value is staged under a sibling account first, so no failure can leave
    /// us with zero copies of the credentials.
    static func upsert(service: String, account: String, data: Data) async throws {
        guard let value = String(data: data, encoding: .utf8) else {
            throw Failure(message: "Credential blob is not UTF-8")
        }
        let staging = stagingAccount(for: account)
        _ = try? await run(["delete-generic-password", "-s", service, "-a", staging])
        let staged = try await run(["add-generic-password", "-s", service, "-a", staging, "-w", value])
        guard staged.status == 0 else {
            throw Failure(message: "Keychain write of \(service) failed (\(staged.status)): "
                + staged.err.trimmingCharacters(in: .whitespacesAndNewlines))
        }
        _ = try? await run(["delete-generic-password", "-s", service, "-a", account])
        let r = try await run(["add-generic-password", "-s", service, "-a", account, "-w", value])
        guard r.status == 0 else {
            throw Failure(message: "Keychain write of \(service) failed (\(r.status)); "
                + "the credentials are preserved in the \"\(staging)\" item: "
                + r.err.trimmingCharacters(in: .whitespacesAndNewlines))
        }
        _ = try? await run(["delete-generic-password", "-s", service, "-a", staging])
    }

    static func stagingAccount(for account: String) -> String { account + "#staging" }

    /// Update the live Claude Code item **in place** (`-U`), preserving the
    /// item and the access grants Claude Code relies on. Matches the item's
    /// real account attribute so we never fork a duplicate item.
    static func upsertLive(service: String, data: Data) async throws {
        guard let value = String(data: data, encoding: .utf8) else {
            throw Failure(message: "Credential blob is not UTF-8")
        }
        let account = await accountAttribute(service: service) ?? NSUserName()
        let r = try await run(["add-generic-password", "-U", "-s", service, "-a", account, "-w", value])
        guard r.status == 0 else {
            throw Failure(message: "Keychain write of \(service) failed (\(r.status)): "
                + r.err.trimmingCharacters(in: .whitespacesAndNewlines))
        }
    }

    /// Update a live keychain item **in place** (`-U`) with an explicit account.
    /// Use when the caller knows the exact account attribute (e.g. Antigravity's
    /// fixed "antigravity" account) to avoid a metadata read before the write.
    static func upsertLive(service: String, account: String, data: Data) async throws {
        guard let value = String(data: data, encoding: .utf8) else {
            throw Failure(message: "Credential blob is not UTF-8")
        }
        let r = try await run(["add-generic-password", "-U", "-s", service, "-a", account, "-w", value])
        guard r.status == 0 else {
            throw Failure(message: "Keychain write of \(service) failed (\(r.status)): "
                + r.err.trimmingCharacters(in: .whitespacesAndNewlines))
        }
    }

    static func delete(service: String, account: String) async throws {
        let r = try await run(["delete-generic-password", "-s", service, "-a", account])
        guard r.status == 0 || r.status == notFound else {
            throw Failure(message: "Keychain delete of \(service) failed (\(r.status)): "
                + r.err.trimmingCharacters(in: .whitespacesAndNewlines))
        }
    }

    /// The `acct` attribute of an existing item — a metadata read, which
    /// never needs ACL authorization (no prompt). Prefers the `NSUserName()`
    /// item when one exists so a stale `"unknown"` item earlier in keychain
    /// order can't divert live writes away from the item Claude Code reads.
    static func accountAttribute(
        service: String,
        user: String = NSUserName(),
        query: ([String]) async throws -> (status: Int32, out: Data, err: String) = { try await run($0) }
    ) async -> String? {
        if let r = try? await query(["find-generic-password", "-s", service, "-a", user]),
           r.status == 0 {
            return user
        }
        guard let r = try? await query(["find-generic-password", "-s", service]),
              r.status == 0 else { return nil }
        let text = (String(data: r.out, encoding: .utf8) ?? "") + r.err
        for line in text.split(separator: "\n")
        where line.contains("\"acct\"<blob>=\"") {
            guard let start = line.range(of: "=\"") else { continue }
            let rest = line[start.upperBound...]
            if let end = rest.lastIndex(of: "\"") {
                return String(rest[..<end])
            }
        }
        return nil
    }
}
