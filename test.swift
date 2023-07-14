import example

// x2

class LogViewController: UIViewController { 

    func foo6(webView: WKWebView, navigationAction: WKNavigationAction) {
        let urlStr = navigationAction.request.url?.absoluteString
        let components = URLComponents(url: urlStr, resolvingAgainstBaseURL: false)
        // vuln log injection
        NSLog("Query value = %@", components.query)
        NSLog("Host value = %@", components.host)
    }
}


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


import Foundation
import SQLite3


// VULNERABLE 
class DatabaseManager {
    var db: OpaquePointer?

    init() {
        // Assume that the database connection setup is done here
    }
    
    func findUser(username: String) {
        let queryStatementString = "SELECT * FROM Users WHERE Username = '\(username)';"
        var queryStatement: OpaquePointer? = nil
        if sqlite3_prepare_v2(db, queryStatementString, -1, &queryStatement, nil) == SQLITE_OK {
            while sqlite3_step(queryStatement) == SQLITE_ROW {
                // Assume that the fetched data is processed here
            }
        }
        sqlite3_finalize(queryStatement)
    }
}


import example
import UIKit
import SafariServices

// x3 TP

// Check UIWebView 
class UIViewController: UIViewController {

    // vuln UIWebView
    @IBOutlet weak var webView: UIWebView!
    
    override func viewDidLoad() {
        super.viewDidLoad()
        // Do any additional setup after loading the view, typically from a nib.
        
        let url = NSURL (string: "https://www.test.net");
        let request = NSURLRequest(URL: url!);
        webView.loadRequest(request);
    }

    override func didReceiveMemoryWarning() {
        super.didReceiveMemoryWarning()
        // Dispose of any resources that can be recreated.
    }


}


class UIWebViewController: UIViewController {
   
    func foo() {
        // vuln UIWebView
        let webView1 = UIWebView()
        webView1.loadHTMLString("<html><body><p>Hello World!</p></body></html>", baseURL: nil)
    }
}





// Check SFSafariViewController
class SafariViewController_test: SafariViewController {
    func foo(_ which: Int) {
        if let url = URL(string: "https://www.test.net/read/\(which + 1)") {
            let config = SFSafariViewController.Configuration()
            config.entersReaderIfAvailable = true
	    // vuln SFSafariViewController
            let vc = SFSafariViewController(url: url, configuration: config)
            present(vc, animated: true)
        }
    }
    
}



import example

// x3 TP

// vuln XXE 
class XXEViewController: ViewController {

    func foo1() {
        var success: Bool
        var rawXmlConvToData: NSData = rawXml.data(using: NSUTF8StringEncoding)
        var myParser: XMLParser = NSXMLParser(data: rawXmlConvToData)
        // vuln xxe
        myParser.shouldResolveExternalEntities = true
        myParser.delegate = self
        myParser.parse()
    }
    

    func foo2(xml: String) {
        parser = NSXMLParser(data: rawXml.dataUsingEncoding(NSUTF8StringEncoding)!)
        parser.delegate = self
        // vuln xxe
        parser.shouldResolveExternalEntities = true
        parser.parse()
    }
    
}
