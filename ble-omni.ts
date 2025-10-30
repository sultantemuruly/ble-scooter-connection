/* Omni BLE client for macOS (TypeScript + @abandonware/noble)
   - Node 18 LTS recommended
   - tsconfig: "module": "CommonJS", "target": "ES2020", "esModuleInterop": true
   - Run examples:
       DEBUG=noble* npx ts-node ble-omni.ts --name=omni --deviceKey=yOTmK50z --action=query
       DEBUG=noble* npx ts-node ble-omni.ts --name=omni --deviceKey=YOURKEY --action=unlock
       DEBUG=noble* npx ts-node ble-omni.ts --name=omni --deviceKey=YOURKEY --action=lock
*/

import noblePkg from "@abandonware/noble";
const noble = noblePkg as any; // CommonJS module; types are dynamic on macOS

// ---- Nordic UART (NUS) UUIDs from the spec ----
const NUS_SERVICE = "6e400001-b5a3-f393-e0a9-e50e24dcca9e";
const NUS_TX = "6e400002-b5a3-f393-e0a9-e50e24dcca9e"; // write
const NUS_RX = "6e400003-b5a3-f393-e0a9-e50e24dcca9e"; // notify

// ---- Protocol constants ----
const STX0 = 0xa3,
  STX1 = 0xa4;
const DEFAULT_DEVICE_KEY = "yOTmK50z";

// ---- CRC8 (Dallas/Maxim) lookup table used by the spec ----
const CRC8_TABLE = Uint8Array.from([
  0, 94, 188, 226, 97, 63, 221, 131, 194, 156, 126, 32, 163, 253, 31, 65, 157,
  195, 33, 127, 252, 162, 64, 30, 95, 1, 227, 189, 62, 96, 130, 220, 35, 125,
  159, 193, 66, 28, 254, 160, 225, 191, 93, 3, 128, 222, 60, 98, 190, 224, 2,
  92, 223, 129, 99, 61, 124, 34, 192, 158, 29, 67, 161, 255, 70, 24, 250, 164,
  39, 121, 155, 197, 132, 218, 56, 102, 229, 187, 89, 7, 219, 133, 103, 57, 186,
  228, 6, 88, 25, 71, 165, 251, 120, 38, 196, 154, 101, 59, 217, 135, 4, 90,
  184, 230, 167, 249, 27, 69, 198, 152, 122, 36, 248, 166, 68, 26, 153, 199, 37,
  123, 58, 100, 134, 216, 91, 5, 231, 185, 140, 210, 48, 110, 237, 179, 81, 15,
  78, 16, 242, 172, 47, 113, 147, 205, 17, 79, 173, 243, 112, 18, 145, 207, 45,
  115, 202, 148, 118, 40, 171, 245, 23, 73, 8, 86, 180, 234, 105, 55, 213, 139,
  87, 9, 235, 181, 54, 104, 138, 212, 149, 203, 41, 119, 244, 170, 72, 22, 233,
  183, 85, 11, 136, 214, 52, 106, 43, 117, 151, 201, 74, 20, 246, 168, 116, 42,
  200, 150, 21, 75, 169, 247, 182, 232, 10, 84, 215, 137, 107, 53,
]);

function crc8(buf: Uint8Array): number {
  let c = 0;
  for (let i = 0; i < buf.length; i++) c = CRC8_TABLE[c ^ buf[i]];
  return c & 0xff;
}

function asciiBytes(s: string): Uint8Array {
  const out = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i) & 0xff;
  return out;
}

const hex = (b: Uint8Array) =>
  [...b].map((v) => v.toString(16).padStart(2, "0")).join(" ");
const sleep = (ms: number) => new Promise((res) => setTimeout(res, ms));

// ---- Frame codec per spec ----
// Frame = STX(2) | LEN(1) | RAND(1) | KEY(1) | CMD(1) | DATA(LEN bytes XORed by RAND) | CRC8(1)
// - CRC8 is over everything before CRC (header + encrypted DATA)
function buildFrame(
  cmd: number,
  dataPlain: Uint8Array,
  keyByte: number,
  verbose = false
): Uint8Array {
  const rand = (Math.random() * 256) & 0xff;
  const dataEnc = new Uint8Array(dataPlain.length);
  for (let i = 0; i < dataPlain.length; i++) dataEnc[i] = dataPlain[i] ^ rand;

  const len = dataEnc.length & 0xff;
  const header = Uint8Array.from([
    STX0,
    STX1,
    len,
    rand,
    keyByte & 0xff,
    cmd & 0xff,
  ]);
  const withoutCrc = new Uint8Array(header.length + dataEnc.length);
  withoutCrc.set(header, 0);
  withoutCrc.set(dataEnc, header.length);
  const c = crc8(withoutCrc);

  const frame = new Uint8Array(withoutCrc.length + 1);
  frame.set(withoutCrc, 0);
  frame[frame.length - 1] = c;

  if (verbose) {
    console.log(
      `TX cmd=0x${cmd.toString(16)} key=0x${(keyByte & 0xff).toString(
        16
      )} rand=0x${rand.toString(16)}`
    );
    console.log("TX hex:", hex(frame));
  }
  return frame;
}

type DecodedFrame = {
  len: number;
  rand: number;
  key: number;
  cmd: number;
  dataPlain: Uint8Array;
  crcOk: boolean;
};

// Robust parser that can handle fragmented notifications
function tryParseFrame(buf: Uint8Array): {
  frame?: DecodedFrame;
  used: number;
} {
  // Need at least minimal header
  if (buf.length < 7) return { used: 0 };
  // Seek STX
  let i = 0;
  while (i + 1 < buf.length && !(buf[i] === STX0 && buf[i + 1] === STX1)) i++;
  if (i > 0) return { used: i }; // drop noise before STX

  if (buf.length < 7) return { used: 0 };
  const len = buf[2];
  const total = 2 + 1 + 1 + 1 + 1 + len + 1; // STX2 + LEN + RAND + KEY + CMD + DATA + CRC
  if (buf.length < total) return { used: 0 };

  const rand = buf[3],
    key = buf[4],
    cmd = buf[5];
  const dataEnc = buf.slice(6, 6 + len);
  const crc = buf[6 + len];
  const crcCalc = crc8(buf.slice(0, 6 + len));
  const dataPlain = new Uint8Array(len);
  for (let j = 0; j < len; j++) dataPlain[j] = dataEnc[j] ^ rand;

  return {
    frame: { len, rand, key, cmd, dataPlain, crcOk: crc === crcCalc },
    used: total,
  };
}

class Reassembler {
  private buf = new Uint8Array(0);
  push(chunk: Uint8Array): DecodedFrame[] {
    // Append
    const merged = new Uint8Array(this.buf.length + chunk.length);
    merged.set(this.buf, 0);
    merged.set(chunk, this.buf.length);
    this.buf = merged;

    const frames: DecodedFrame[] = [];
    while (true) {
      const { frame, used } = tryParseFrame(this.buf);
      if (used === 0) break;
      this.buf = this.buf.slice(used);
      if (frame) frames.push(frame);
    }
    return frames;
  }
}

// ---- BLE helper: wait for adapter ready ----
async function waitPoweredOn(): Promise<void> {
  if (noble.state === "poweredOn") return;
  await new Promise<void>((resolve, reject) => {
    const on = (s: string) => {
      if (s === "poweredOn") {
        noble.removeListener("stateChange", on);
        resolve();
      } else if (s === "unsupported" || s === "unauthorized") {
        noble.removeListener("stateChange", on);
        reject(new Error(`Bluetooth ${s} by macOS`));
      }
    };
    noble.on("stateChange", on);
  });
}

// ---- Connect & get TX/RX characteristics ----
type TxRx = { tx: any; rx: any; periph: any; name: string };

async function connectNUS({
  nameContains,
}: {
  nameContains?: string;
}): Promise<TxRx> {
  await waitPoweredOn();

  return new Promise<TxRx>((resolve, reject) => {
    const serviceFilter = [NUS_SERVICE];
    let resolved = false;

    const onDiscover = async (p: any) => {
      try {
        const adv = p.advertisement || {};
        const localName = adv.localName || "";
        const nameOk = nameContains
          ? (localName || "").toLowerCase().includes(nameContains.toLowerCase())
          : true;

        // Check advertised services for NUS
        const srvUuids: string[] = (adv.serviceUuids || []).map((u: string) =>
          u.toLowerCase()
        );
        const nusAdvertised = srvUuids.includes("6e400001");

        if (!nameOk && !nusAdvertised) return;

        noble.stopScanning();
        p.removeListener("disconnect", onDisc);
        p.once("disconnect", onDisc);

        await p.connectAsync();
        const { characteristics } =
          await p.discoverSomeServicesAndCharacteristicsAsync(
            [NUS_SERVICE],
            [NUS_TX, NUS_RX]
          );
        const tx = characteristics.find(
          (c: any) => c.uuid.toLowerCase() === NUS_TX.replace(/-/g, "")
        );
        const rx = characteristics.find(
          (c: any) => c.uuid.toLowerCase() === NUS_RX.replace(/-/g, "")
        );
        if (!tx || !rx) throw new Error("TX/RX characteristics not found");

        await rx.subscribeAsync();
        resolved = true;
        resolve({
          tx,
          rx,
          periph: p,
          name: localName || p.address || "unknown",
        });
      } catch (e: any) {
        if (!resolved) reject(e);
      }
    };

    const onDisc = () => {
      if (!resolved) reject(new Error("Disconnected before service discovery"));
    };

    noble.on("discover", onDiscover);

    noble.startScanningAsync(serviceFilter, false).catch(reject);

    // Safety timeout
    (async () => {
      for (let i = 0; i < 30 && !resolved; i++) await sleep(1000);
      if (!resolved) {
        noble.removeListener("discover", onDiscover);
        reject(new Error("Scan timeout: no Omni device found"));
      }
    })();
  });
}

// ---- Round-trip sender (with reassembly & per-CMD wait) ----
async function sendAndWait(
  tx: any,
  rx: any,
  frame: Uint8Array,
  expectCmd: number,
  timeoutMs = 4000,
  verbose = false
): Promise<DecodedFrame> {
  return new Promise<DecodedFrame>(async (resolve, reject) => {
    const asm = new Reassembler();
    let timer: NodeJS.Timeout | null = setTimeout(() => {
      rx.removeListener("data", onData);
      reject(new Error("Timeout waiting for response"));
    }, timeoutMs);

    function finish(dec: DecodedFrame) {
      if (timer) clearTimeout(timer);
      rx.removeListener("data", onData);
      resolve(dec);
    }

    function onData(chunk: Buffer) {
      const frames = asm.push(new Uint8Array(chunk));
      for (const f of frames) {
        if (verbose) {
          console.log(
            `RX cmd=0x${f.cmd.toString(16)} rand=0x${f.rand.toString(
              16
            )} key=0x${f.key.toString(16)} crcOk=${f.crcOk}`
          );
          console.log("RX hex (full frame):", hex(chunk));
          console.log("RX data (plain):", hex(f.dataPlain));
        }
        if (f.cmd === expectCmd) return finish(f);
      }
    }

    rx.on("data", onData);
    await tx.writeAsync(Buffer.from(frame), /*withoutResponse*/ true);
  });
}

// ---- High-level protocol ops ----
async function cmdHandshake(
  tx: any,
  rx: any,
  deviceKey: string,
  verbose = false
): Promise<number> {
  const payload = asciiBytes(deviceKey);
  if (payload.length !== 8)
    throw new Error("Device KEY must be exactly 8 ASCII bytes");
  const frame = buildFrame(0x01, payload, /*KEY*/ 0x00, verbose);
  const rep = await sendAndWait(tx, rx, frame, 0x01, 30000, verbose);
  if (!rep.crcOk) throw new Error("CRC error in 0x01 reply");
  if (rep.dataPlain.length < 2) throw new Error("Bad 0x01 reply payload");
  const status = rep.dataPlain[0];
  const sessionKey = rep.dataPlain[1] & 0xff;
  if (status !== 1) throw new Error("Device KEY rejected by scooter");
  return sessionKey;
}

async function cmdQueryInfo(tx: any, rx: any, sk: number, verbose = false) {
  const data = Uint8Array.from([0x01]); // control byte per spec
  const frame = buildFrame(0x31, data, sk, verbose);
  const rep = await sendAndWait(tx, rx, frame, 0x31, 4000, verbose);
  if (!rep.crcOk) throw new Error("CRC error in 0x31 reply");
  console.log("IoT info (0x31) data:", hex(rep.dataPlain));
}

async function cmdUnlock(
  tx: any,
  rx: any,
  sk: number,
  userId = 1,
  unixTs = Math.floor(Date.now() / 1000),
  noTimerReset = false,
  verbose = false
) {
  // [0]=0x01, [1..4]=userId (big-endian), [5..8]=timestamp (big-endian), [9]=status flag
  const d = new Uint8Array(10);
  d[0] = 0x01;
  d[1] = (userId >>> 24) & 0xff;
  d[2] = (userId >>> 16) & 0xff;
  d[3] = (userId >>> 8) & 0xff;
  d[4] = userId & 0xff;
  d[5] = (unixTs >>> 24) & 0xff;
  d[6] = (unixTs >>> 16) & 0xff;
  d[7] = (unixTs >>> 8) & 0xff;
  d[8] = unixTs & 0xff;
  d[9] = noTimerReset ? 0xa0 : 0x00;

  const frame = buildFrame(0x05, d, sk, verbose);
  const rep = await sendAndWait(tx, rx, frame, 0x05, 5000, verbose);
  if (!rep.crcOk) throw new Error("CRC error in 0x05 reply");

  // Mandatory ACK (DATA=0x02), no reply expected
  const ack = buildFrame(0x05, Uint8Array.from([0x02]), sk, verbose);
  await tx.writeAsync(Buffer.from(ack), true);
  console.log("Unlock sent and ACKed.");
}

async function cmdLock(tx: any, rx: any, sk: number, verbose = false) {
  const frame = buildFrame(0x15, Uint8Array.from([0x01]), sk, verbose);
  const rep = await sendAndWait(tx, rx, frame, 0x15, 5000, verbose);
  if (!rep.crcOk) throw new Error("CRC error in 0x15 reply");

  const ack = buildFrame(0x15, Uint8Array.from([0x02]), sk, verbose);
  await tx.writeAsync(Buffer.from(ack), true);
  console.log("Lock sent and ACKed.");
}

// ---- CLI glue ----
type Args = {
  name?: string; // substring of localName to match
  deviceKey?: string; // 8 ASCII chars
  action?: "query" | "unlock" | "lock";
  userId?: string;
  noTimerReset?: string | boolean;
  verbose?: string | boolean;
};

function parseArgs(): Args {
  const out: any = {};
  for (const a of process.argv.slice(2)) {
    const [k, v] = a.split("=");
    const key = k.replace(/^--/, "");
    out[key] = v === undefined ? true : v;
  }
  return out as Args;
}

(async () => {
  const args = parseArgs();
  const name = args.name;
  const deviceKey = (args.deviceKey || DEFAULT_DEVICE_KEY) as string;
  const action = (args.action || "query") as Args["action"];
  const verbose = !!args.verbose;

  if (process.platform === "darwin" && (args as any).mac) {
    console.warn(
      "Note: macOS CoreBluetooth does not expose device MAC addresses. Use --name=... or rely on service UUID filtering."
    );
  }

  console.log("Scanning for Omni scooter…", {
    name: name ?? "(any with NUS service)",
  });
  const {
    tx,
    rx,
    periph,
    name: foundName,
  } = await connectNUS({ nameContains: name });
  console.log(`Connected to: ${foundName}`);

  // Handshake MUST be within ~5s of connect
  console.log("Performing 0x01 handshake…");
  const sessionKey = await cmdHandshake(tx, rx, deviceKey, verbose);
  console.log("Session KEY:", "0x" + sessionKey.toString(16).padStart(2, "0"));

  if (action === "query") {
    await cmdQueryInfo(tx, rx, sessionKey, verbose);
  } else if (action === "unlock") {
    const userId = args.userId ? parseInt(args.userId, 10) : 1;
    const noTimerReset =
      args.noTimerReset === true || args.noTimerReset === "true";
    await cmdUnlock(
      tx,
      rx,
      sessionKey,
      userId,
      Math.floor(Date.now() / 1000),
      noTimerReset,
      verbose
    );
  } else if (action === "lock") {
    await cmdLock(tx, rx, sessionKey, verbose);
  }

  console.log("Done. Disconnecting…");
  await periph.disconnectAsync();
  process.exit(0);
})().catch((err) => {
  console.error("ERROR:", err?.message || err);
  process.exit(1);
});
