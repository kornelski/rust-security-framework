//
//  ios_testerTests.swift
//  ios-testerTests
//
//  Created by Daniel Brotsky on 12/17/21.
//

import XCTest
@testable import ios_tester

class ios_testerTests: XCTestCase {

//    override func setUpWithError() throws {
//        // Put setup code here. This method is called before the invocation of each test method in the class.
//    }
//
//    override func tearDownWithError() throws {
//        // Put teardown code here. This method is called after the invocation of each test method in the class.
//    }

    func testExample() throws {
        let input: String = "test-password"
        XCTAssertNotNil(try? PasswordOps.setPassword(service: "test-service", user: "test-user", password: input))
        let result: String = try! PasswordOps.getPassword(service: "test-service", user: "test-user")
        XCTAssertEqual(input, result)
        XCTAssertNotNil(try? PasswordOps.deletePassword(service: "test-service", user: "test-user"))
    }

//    func testPerformanceExample() throws {
//        // This is an example of a performance test case.
//        self.measure {
//            // Put the code you want to measure the time of here.
//        }
//    }

}
