import example
import UIKit
import SafariServices
import WebKit
import Foundation
import SQLite3

// SAFE SQL Query
func findUser(username: String) {
    let queryStatementString = "SELECT * FROM Users WHERE Username = ?;"
    var queryStatement: OpaquePointer? = nil
    if sqlite3_prepare_v2(db, queryStatementString, -1, &queryStatement, nil) == SQLITE_OK {
        sqlite3_bind_text(queryStatement, 1, username, -1, SQLITE_TRANSIENT)
        while sqlite3_step(queryStatement) == SQLITE_ROW {
            // Assume that the fetched data is processed here
        }
    }
    sqlite3_finalize(queryStatement)
}


// safe webkit, doesnt trigger a FP
class ViewController: UIViewController, WKNavigationDelegate {

    var webView: WKWebView!

    override func viewDidLoad() {
        super.viewDidLoad()

        webView = WKWebView()
        webView.navigationDelegate = self
        view = webView

        if let url = URL(string: "https://www.test.net") {
            let request = URLRequest(url: url)
            webView.load(request)
        }
    }
}

// safe XXE, doesnt trigger a FP
class XXEViewController: UIViewController, XMLParserDelegate {

    var parser: XMLParser!
    
    func parseXmlData(data: Data) {
        parser = XMLParser(data: data)
        parser.delegate = self
        // Avoid XXE by disallowing the resolution of external entities
        parser.shouldResolveExternalEntities = false
        parser.parse()
    }
    
    func foo1(rawXml: String) {
        guard let data = rawXml.data(using: .utf8) else {
            print("Failed to convert XML string to data")
            return
        }
        parseXmlData(data: data)
    }

    func foo2(rawXml: String) {
        guard let data = rawXml.data(using: .utf8) else {
            print("Failed to convert XML string to data")
            return
        }
        parseXmlData(data: data)
    }
    
    // rest of the XMLParserDelegate methods would go here...
}
