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