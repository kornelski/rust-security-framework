//
//  ContentView.swift
//  ios-test-harness
//

import SwiftUI

struct ContentView: View {
    @State var showAlert = false;
    
    var body: some View {
        Button("Run Test") {
            TestRunner.runTest()
            showAlert = true
        }
        .alert(isPresented: $showAlert) {
            Alert(title: Text("Test Result"),
                  message: Text("Tests ran without crash!"))
        }
    }
}

struct ContentView_Previews: PreviewProvider {
    static var previews: some View {
        ContentView()
    }
}
