//
//  static_test_harnessTests.swift
//  static-test-harnessTests
//
//  Created by Daniel Brotsky on 1/29/22.
//

import XCTest
@testable import ios_test_harness

class static_test_harnessTests: XCTestCase {

    func testRun() throws {
        TestRunner.runTest()
    }

}
