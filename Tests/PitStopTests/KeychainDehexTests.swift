import XCTest
@testable import PitStop

final class KeychainDehexTests: XCTestCase {
    private func hex(_ data: Data) -> Data {
        Data(data.map { String(format: "%02x", $0) }.joined().utf8)
    }

    func testDecodesHexOfPrettyJSON() {
        let pretty = Data("{\n  \"access_token\": \"AT\"\n}".utf8)
        XCTAssertEqual(Keychain.dehexed(hex(pretty)), pretty)
    }

    func testDecodesHexOfGoKeyringString() {
        let raw = Data("go-keyring-base64:aGVsbG8=".utf8)
        XCTAssertEqual(Keychain.dehexed(hex(raw)), raw)
    }

    func testPassesThroughPlainJSON() {
        let json = Data(#"{"access_token":"AT"}"#.utf8)
        XCTAssertEqual(Keychain.dehexed(json), json)
    }

    func testPassesThroughHexThatDecodesToGarbage() {
        let junk = Data("deadbeef".utf8)   // decodes to non-UTF8/non-JSON bytes
        XCTAssertEqual(Keychain.dehexed(junk), junk)
    }

    func testPassesThroughOddLengthAndEmpty() {
        XCTAssertEqual(Keychain.dehexed(Data("abc".utf8)), Data("abc".utf8))
        XCTAssertEqual(Keychain.dehexed(Data()), Data())
    }

    func testLiveReadPrefersUserAccountOverStaleServiceMatch() async throws {
        let staleUnknown = Data(#"{"claudeAiOauth":{"accessToken":"stale"}}"#.utf8)
        let liveUser = Data(#"{"claudeAiOauth":{"accessToken":"live"}}"#.utf8)
        var queriedAccounts: [String?] = []

        let result = try await Keychain.read(
            service: CredentialBlob.liveService,
            account: nil,
            user: "jack.reis",
            fetch: { account in
                queriedAccounts.append(account)
                if account == "jack.reis" { return liveUser }
                if account == nil { return staleUnknown }
                return nil
            })

        XCTAssertEqual(result, liveUser)
        XCTAssertEqual(queriedAccounts, ["jack.reis"])
    }

    func testLiveReadFallsBackToServiceMatchWhenUserAccountMissing() async throws {
        let fallbackBlob = Data(#"{"claudeAiOauth":{"accessToken":"fallback"}}"#.utf8)
        var queriedAccounts: [String?] = []

        let result = try await Keychain.read(
            service: CredentialBlob.liveService,
            account: nil,
            user: "jack.reis",
            fetch: { account in
                queriedAccounts.append(account)
                if account == nil { return fallbackBlob }
                return nil
            })

        XCTAssertEqual(result, fallbackBlob)
        XCTAssertEqual(queriedAccounts, ["jack.reis", nil])
    }

    func testAccountAttributePrefersUserAccountWhenPresent() async {
        var queries: [[String]] = []
        let resolved = await Keychain.accountAttribute(
            service: CredentialBlob.liveService,
            user: "jack.reis",
            query: { args in
                queries.append(args)
                if args == ["find-generic-password", "-s", CredentialBlob.liveService, "-a", "jack.reis"] {
                    return (0, Data(), "")
                }
                return (0, Data("\"acct\"<blob>=\"unknown\"\n".utf8), "")
            })

        XCTAssertEqual(resolved, "jack.reis")
        XCTAssertEqual(queries.count, 1)
    }

    func testAccountAttributeFallsBackToUnscopedMetadataWhenUserAccountMissing() async {
        let resolved = await Keychain.accountAttribute(
            service: CredentialBlob.liveService,
            user: "jack.reis",
            query: { args in
                if args.contains("-a") {
                    return (44, Data(), "")
                }
                return (0, Data("    \"acct\"<blob>=\"claude-code-user\"\n".utf8), "")
            })

        XCTAssertEqual(resolved, "claude-code-user")
    }
}
