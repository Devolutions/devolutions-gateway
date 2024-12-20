export function convertTRPtoCast(fileArray) {
  const castHeader = {
    version: 2,
    width: 0,
    height: 0,
    duration: 0,
  };
  const castEvents = [];

  let time = 0.0;
  let position = 0;
  while (position < fileArray.length) {
    const timer = readUInt32(fileArray, position);
    const type = readUInt16(fileArray, position + 4);
    const size = readUInt16(fileArray, position + 6);
    const chunk = fileArray.subarray(position + 8, position + 8 + size);
    position += 8 + size;
    time += timer / 1000;
    if (castEvents.length > 0 && castEvents[castEvents.length - 1][0] === time) {
      time += 0.001;
    }
    if (type === 0) {
      // RECORD_CHUNK_TERMINAL_OUTPUT
      const data = new TextDecoder().decode(chunk);
      castEvents.push([time, 'o', data]);
    } else if (type === 1) {
      // RECORD_CHUNK_USER_INPUT
      const data = new TextDecoder().decode(chunk);
      castEvents.push([time, 'i', data]);
    } else if (type === 2) {
      // RECORD_CHUNK_SIZE_CHANGE
      const width = readUInt16(chunk, 0);
      const height = readUInt16(chunk, 2);
      if (castHeader.width === 0) {
        castHeader.width = width;
        castHeader.height = height;
      } else {
        castEvents.push([time, 'r', width + 'x' + height]);
      }
    } else if (type === 4) {
      // RECORD_CHUNK_TERMINAL_SETUP
      // What this is for here? not used, commented out for now
      // const tagCount = size / 6;
      // for (let i = 0; i < tagCount; i++) {
      //   const _tag = readUInt16(chunk, i * 6);
      //   const _tagValue = readUInt32(chunk, i * 6 + 2);
      // }
    }
  }
  castHeader.duration = time;
  let castFile = JSON.stringify(castHeader) + '\n';
  for (const event of castEvents) {
    castFile += JSON.stringify(event) + '\n';
  }
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
