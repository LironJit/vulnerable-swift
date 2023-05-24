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



// safe XXE, doesnt trigger a FP

import UIKit

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
