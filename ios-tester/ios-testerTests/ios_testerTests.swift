//
//  ios_testerTests.swift
//  ios-testerTests
//
//  Created by Daniel Brotsky on 12/17/21.
//

import XCTest
@testable import ios_tester

class ios_testerTests: XCTestCase {

    func testRoundtrip() throws {
        let input: String = "testRoundtrip"
        XCTAssertNotNil(try? PasswordOps.setPassword(service: "testRoundtrip", user: "testRoundtrip", password: input))
        let result: String = try! PasswordOps.getPassword(service: "testRoundtrip", user: "testRoundtrip")
        XCTAssertEqual(input, result)
        XCTAssertNotNil(try? PasswordOps.deletePassword(service: "testRoundtrip", user: "testRoundtrip"))
    }
    
    func testMissing() throws {
        XCTAssertNil(try? PasswordOps.getPassword(service: "testMissing", user: "testMissing"))
    }
}
