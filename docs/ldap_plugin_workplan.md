## Workplan for writing the LDAP Authorization Plugin

- [x] Design and decide on best layout of JSON file (perhaps go with one design but keep others for potential feedback from users?)
- [x] Create logic for parsing and querying the JSON file
- [x] Create logic for parsing the path of the file requested and using it to search the JSON file to get relevant LDAP attributes to search for
- [x] Code request/response code to LDAP server, with exception handling
- [x] Code acceptance/rejection of user based on either LDAP response or their IP address
- [x] Write selenium tests that should allow access to a resource with protection on
- [x] Write selenium tests that should deny access to a resource with protection on
