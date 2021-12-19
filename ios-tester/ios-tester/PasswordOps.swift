//
//  PasswordOps.swift
//  ios-tester
//
//  Created by Daniel Brotsky on 12/18/21.
//

import Foundation

enum PasswordError: Error {
    case notFound
    case notString(Data)
    case unexpected(OSStatus)
}

class PasswordOps {
    static func setPassword(service: String, user: String, password: String) throws {
        let data = Data(password.utf8)
        let status = SecSetGenericPassword(service as CFString, user as CFString, data as CFData)
        guard status == errSecSuccess else {
            throw PasswordError.unexpected(status)
        }
    }
    
static func getPassword(service: String, user: String) throws -> String {
    var result: Unmanaged<CFData>?
    let status = SecCopyGenericPassword(service as CFString, user as CFString, &result)
    if status == errSecItemNotFound {
        throw PasswordError.notFound
    }
    guard status == errSecSuccess else {
        throw PasswordError.unexpected(status)
    }
    if let data = result?.takeRetainedValue() as Data? {
        if let password = String.init(bytes: data, encoding: .utf8) {
            return password
        } else {
            throw PasswordError.notString(data)
        }
    }
    // somehow the call returned success with null data,
    // this shouldn't happen so we'll call it a decode error
    throw PasswordError.unexpected(errSecDecode)
}

    static func deletePassword(service: String, user: String) throws {
        let status = SecDeleteGenericPassword(service as CFString, user as CFString)
        guard status == errSecSuccess else {
            throw PasswordError.unexpected(status)
        }
    }
}
