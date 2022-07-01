# C# DefaultSetter

[![Latest Version](https://img.shields.io/badge/Latest-v1.0.2-green.svg)]()
[![MIT License](https://img.shields.io/github/license/mashape/apistatus.svg)]()

Default app installer to associate with file/protocol type in Windows 10/11.

## Features
* Generate User Choice Hash.
* Set File Type Association.
* Set Protocol Association.

## Usage
##### Set Microsoft Edge as default .html files opener:
```
//If changed successfully, the result will be empty.
string result = DefaultSetter.TrySetExtensionDefaultApp("MSEdgeHTM", ".html");
```

##### Set Microsoft Edge as default for http protocol:
```
//If changed successfully, the result will be empty.
string result = DefaultSetter.TrySetProtocolDefaultApp("MSEdgeHTM", "http");
```

##### Get the generated hash without registry changes:
```
//Returns the generated hash or null on failure.
string? hash = DefaultSetter.GenerateHash("MSEdgeHTM", "https");
```

## Additional Instructions

##### Setting your own UserSID for hash generation:
```
//Set null to reset.
DefaultSetter.UserSID = "CustomSID";
```

## License

Usage is provided under the [MIT](https://choosealicense.com/licenses/mit/) License.

Copyright © 2022, Inseries.dev
