//
//  ContentView.swift
//  ios-tester
//
//  Created by Daniel Brotsky on 12/17/21.
//

import SwiftUI

struct ContentView: View {
    @State var count = 1
    @State var password = "password0"
    
    var body: some View {
        Form {
            Section("Password") {
                TextField("Password", text: $password)
                Button("Set and Read") {
                    setAndRead()
                }
            }
        }
    }
    
    func setAndRead() {
        password = "password\(count)"
        try! PasswordOps.setPassword(service: "service", user: "user", password: password)
        password = try! PasswordOps.getPassword(service: "service", user: "user")
        try! PasswordOps.deletePassword(service: "service", user: "user")
        count += 1
    }
}

struct ContentView_Previews: PreviewProvider {
    static var previews: some View {
        ContentView()
    }
}
