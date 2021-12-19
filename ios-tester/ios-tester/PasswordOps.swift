//
//  PasswordOps.swift
//  ios-tester
//
//  Created by Daniel Brotsky on 12/18/21.
//

import Foundation

enum PasswordError: Error {
    case notFound
    case notString([UInt8])
    case unexpected(OSStatus)
}

class PasswordOps {
    static func setPassword(service: String, user: String, password: String) throws {
        let bytes: [UInt8] = Array(password.utf8)
        let status = set_generic_password(service, user, bytes, UInt64(bytes.count))
        guard status == errSecSuccess else {
            throw PasswordError.unexpected(status)
        }
    }
    
static func getPassword(service: String, user: String) throws -> String {
        var bytes: [UInt8] = Array(repeating: 0, count: 2048)
        var pwlen: UInt64 = 0
        let status = get_generic_password(service, user, &bytes, 1024, &pwlen)
        if status == errSecBufferTooSmall {
            throw PasswordError.unexpected(errSecDataTooLarge)
        } else if status != errSecSuccess {
            throw PasswordError.unexpected(status)
        }
    if let password = String(bytes: bytes[0..<Int(pwlen)], encoding: .utf8) {
            return password
        } else {
            throw PasswordError.notString(bytes)
        }
    }

    static func deletePassword(service: String, user: String) throws {
        let status = delete_generic_password(service, user)
        guard status == errSecSuccess else {
            throw PasswordError.unexpected(status)
        }
    }
}
