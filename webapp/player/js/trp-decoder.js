
export function convertTRPtoCast(fileArray) {
  var castHeader = {
    version: 2,
    width: 0,
    height: 0,
  };
  var castEvents = [];

  var time = 0.0;
  var position = 0;
  while (position < fileArray.length) {
    var timer = readUInt32(fileArray, position);
    var type = readUInt16(fileArray, position + 4);
    var size = readUInt16(fileArray, position + 6);
    var chunk = fileArray.subarray(position + 8, position + 8 + size);
    position += 8 + size;
    time += timer / 1000;
    if (type == 0) {
      // RECORD_CHUNK_TERMINAL_OUTPUT
      var data = new TextDecoder().decode(chunk);
      castEvents.push([time, "o", data]);
    } else if (type == 1) {
      // RECORD_CHUNK_USER_INPUT
      var data = new TextDecoder().decode(chunk);
      castEvents.push([time, "i", data]);
    } else if (type == 2) {
      // RECORD_CHUNK_SIZE_CHANGE
      var width = readUInt16(chunk, 0);
      var height = readUInt16(chunk, 2);
      if (castHeader.width == 0) {
        castHeader.width = width;
        castHeader.height = height;
      } else {
        castEvents.push([time, "r", width + "x" + height]);
      }
    } else if (type == 4) {
      // RECORD_CHUNK_TERMINAL_SETUP
      var tagCount = size / 6;
      for (var i = 0; i < tagCount; i++) {
        var tag = readUInt16(chunk, i * 6);
        var tagValue = readUInt32(chunk, i * 6 + 2);
      }
    }
  }
  castHeader.duration = time;
  var castFile = JSON.stringify(castHeader) + "\n";
  castEvents.forEach((event) => {
    castFile += JSON.stringify(event) + "\n";
  });
  return castFile;
}

function readUInt32(array, position) {
  return (
    ((array[position + 3] << 24) & 0xff000000) |
    ((array[position + 2] << 16) & 0xff0000) |
    ((array[position + 1] << 8) & 0xff00) |
    array[position + 0]
  );
}

function readUInt16(array, position) {
  return ((array[position + 1] << 8) & 0xff00) | array[position];
}