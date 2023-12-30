export function printStacktrace() {
  var stacktrace = Java.use("android.util.Log")
    .getStackTraceString(Java.use("java.lang.Exception").$new())
    .replace("java.lang.Exception", "");
  console.log(stacktrace);
}

export function printMap(map) {
  var mapIter = map.entrySet().iterator();
  while (mapIter.hasNext()) {
    console.log(mapIter.next());
  }
}

export function decodeMode(mode) {
  if (mode == 1) return "Encrypt mode";
  else if (mode == 2) return "Decrypt mode";
  else if (mode == 3) return "Wrap mode";
  else if (mode == 4) return "Unwrap mode";
}

export function charArrayToString(charArray) {
  if (charArray == null) return "(null)";
  else return StringCls.$new(charArray);
}

export function dumpByteArray(title, byteArr) {
  if (byteArr != null) {
    try {
      var buff = new ArrayBuffer(byteArr.length);
      var dtv = new DataView(buff);
      for (var i = 0; i < byteArr.length; i++) {
        /*
        Frida sucks sometimes and returns different byteArr.length between ArrayBuffer(byteArr.length) and for(..; i < byteArr.length;..).
        It occurred even when Array.copyOf was done to work on copy.
        */
        dtv.setUint8(i, byteArr[i]);
      }
      console.log(title + ":\n");
      console.log(_hexdumpJS(dtv.buffer, 0, byteArr.length));
    } catch (error) {
      console.log("Exception has occured in hexdump");
    }
  } else {
    console.log("byteArr is null!");
  }
}

function _fillUp(value, count, fillWith) {
  var l = count - value.length;
  var ret = "";
  while (--l > -1) ret += fillWith;
  return ret + value;
}

function _hexdumpJS(arrayBuffer, offset, length) {
  var view = new DataView(arrayBuffer);
  offset = offset || 0;
  length = length || arrayBuffer.byteLength;

  var out =
    _fillUp("Offset", 8, " ") +
    "  00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F\n";
  var row = "";
  for (var i = 0; i < length; i += 16) {
    row += _fillUp(offset.toString(16).toUpperCase(), 8, "0") + "  ";
    var n = Math.min(16, length - offset);
    var string = "";
    for (var j = 0; j < 16; ++j) {
      if (j < n) {
        var value = view.getUint8(offset);
        string += value >= 32 && value < 128 ? String.fromCharCode(value) : ".";
        row += _fillUp(value.toString(16).toUpperCase(), 2, "0") + " ";
        offset++;
      } else {
        row += "   ";
        string += " ";
      }
    }
    row += " " + string + "\n";
  }
  out += row;
  return out;
}
