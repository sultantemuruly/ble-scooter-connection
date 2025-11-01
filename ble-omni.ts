/**
 * Omni BLE client for macOS (TypeScript + @abandonware/noble)
 * - Node 18 LTS
 * - tsconfig: { "module": "CommonJS", "target": "ES2020", "esModuleInterop": true }
 *
 * Install:
 *   npm i @abandonware/noble
 *   npm i -D ts-node typescript @types/node
 *
 * Run examples:
 *   DEBUG=noble* npx ts-node ble-omni.ts --name=Scooter --deviceKey=YOUR8KEY --action=query --verbose
 *   DEBUG=noble* npx ts-node ble-omni.ts --id=<corebluetooth-id> --deviceKey=YOUR8KEY --action=unlock
 *
 * Notes in this rewrite (handshake robustness):
 *   - Enables notifications and waits ~250ms before first write (CoreBluetooth settle).
 *   - Prefers write-with-response for 1st packet; falls back to without-response.
 *   - Handles device Command Error (CMD 0x10) with readable messages.
 *   - Longer timeouts + one retry on handshake in case first notify is missed.
 */

import noblePkg from "@abandonware/noble";
const noble = noblePkg as any; // CJS-compatible

// Nordic UART (NUS) UUIDs
const NUS_SERVICE = "6e400001-b5a3-f393-e0a9-e50e24dcca9e";
const NUS_TX = "6e400002-b5a3-f393-e0a9-e50e24dcca9e"; // write
const NUS_RX = "6e400003-b5a3-f393-e0a9-e50e24dcca9e"; // notify

// Protocol constants
const STX0 = 0xa3,
  STX1 = 0xa4;
const DEFAULT_DEVICE_KEY = "yOTmK50z"; // not guaranteed to work; real fleets change this

// Dallas/Maxim CRC8 table
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

const hex = (b: ArrayLike<number>) =>
  Array.from(b, (v) => v.toString(16).padStart(2, "0")).join(" ");
const sleep = (ms: number) => new Promise((res) => setTimeout(res, ms));

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

/** Build frame per Omni spec:
 * RAND field on wire is r+0x32; KEY/CMD/DATA are XORed with r, CRC over encoded header+data.
 * For the handshake (cmd=0x01) the header KEY MUST be 0x00.
 * For subsequent commands, header KEY = sessionKey returned by handshake.
 */
function buildFrame(
  cmd: number,
  dataPlain: Uint8Array,
  keyByte: number,
  verbose = false
): Uint8Array {
  const r = (Math.random() * 256) | 0;
  const r1 = (r + 0x32) & 0xff;

  const keyX = (keyByte & 0xff) ^ r;
  const cmdX = (cmd & 0xff) ^ r;

  const enc = new Uint8Array(dataPlain.length);
  for (let i = 0; i < dataPlain.length; i++) enc[i] = dataPlain[i] ^ r;

  const len = enc.length & 0xff;
  const header = Uint8Array.from([STX0, STX1, len, r1, keyX, cmdX]);

  const preCrc = new Uint8Array(header.length + enc.length);
  preCrc.set(header, 0);
  preCrc.set(enc, header.length);

  const c = crc8(preCrc);

  const out = new Uint8Array(preCrc.length + 1);
  out.set(preCrc, 0);
  out[out.length - 1] = c;

  if (verbose) {
    console.log(
      `TX cmd=0x${cmd.toString(16)} r=0x${r.toString(
        16
      )} randField=0x${r1.toString(16)}`
    );
    console.log("TX hex:", hex(out));
  }
  return out;
}

type DecodedFrame = {
  len: number;
  rand: number;
  key: number;
  cmd: number;
  dataPlain: Uint8Array;
  crcOk: boolean;
};

function tryParseFrame(buf: Uint8Array): {
  frame?: DecodedFrame;
  used: number;
} {
  if (buf.length < 7) return { used: 0 };

  // seek STX
  let i = 0;
  while (i + 1 < buf.length && !(buf[i] === STX0 && buf[i + 1] === STX1)) i++;
  if (i > 0) return { used: i };

  if (buf.length < 7) return { used: 0 };
  const len = buf[2];
  const total = 2 + 1 + 1 + 1 + 1 + len + 1;
  if (buf.length < total) return { used: 0 };

  const randField = buf[3];
  const r = (randField - 0x32) & 0xff;

  const keyWire = buf[4];
  const cmdWire = buf[5];
  const dataEnc = buf.slice(6, 6 + len);
  const crc = buf[6 + len];
  const crcCalc = crc8(buf.slice(0, 6 + len));

  const key = keyWire ^ r;
  const cmd = cmdWire ^ r;
  const dataPlain = new Uint8Array(len);
  for (let j = 0; j < len; j++) dataPlain[j] = dataEnc[j] ^ r;

  return {
    frame: { len, rand: r, key, cmd, dataPlain, crcOk: crc === crcCalc },
    used: total,
  };
}

class Reassembler {
  private buf = new Uint8Array(0);
  push(chunk: Uint8Array): DecodedFrame[] {
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

// BLE helpers
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

type TxRx = { tx: any; rx: any; periph: any; name: string };

function charSupportsWrite(ch: any) {
  const p: string[] = ch?.properties || [];
  return p.includes("write");
}
function charSupportsWriteWoResp(ch: any) {
  const p: string[] = ch?.properties || [];
  return p.includes("writeWithoutResponse");
}
async function writeFrame(tx: any, frame: Uint8Array) {
  // Prefer write-with-response; fallback to without-response if needed
  if (charSupportsWrite(tx)) {
    try {
      await tx.writeAsync(Buffer.from(frame), /*withoutResponse=*/ false);
      return;
    } catch {
      // fall through
    }
  }
  if (charSupportsWriteWoResp(tx)) {
    await tx.writeAsync(Buffer.from(frame), /*withoutResponse=*/ true);
    return;
  }
  // If neither property is present, try with-response once (legacy noble sometimes works)
  await tx.writeAsync(Buffer.from(frame), /*withoutResponse=*/ false);
}

async function connectNUS(
  opts: {
    id?: string;
    nameContains?: string;
    scanMs?: number;
    verbose?: boolean;
  } = {}
): Promise<TxRx> {
  const { id, nameContains, scanMs = 25000, verbose = false } = opts;
  await waitPoweredOn();

  return new Promise<TxRx>((resolve, reject) => {
    let resolved = false;
    const deadline = Date.now() + scanMs;

    const onDiscover = async (p: any) => {
      try {
        const adv = p.advertisement || {};
        const localName = (adv.localName || "").toLowerCase();

        // Select target:
        if (id) {
          if (p.id !== id) return;
        } else if (nameContains) {
          if (!localName.includes(nameContains.toLowerCase())) return;
        } else {
          // no filter provided: require NUS advertised or a "scooter-ish" name
          const srvUuids: string[] = (adv.serviceUuids || []).map((u: string) =>
            u.toLowerCase()
          );
          const nusAdvertised = srvUuids.includes("6e400001");
          if (!nusAdvertised && !localName.includes("scooter")) return;
        }

        if (verbose) {
          const md: Buffer | undefined = adv.manufacturerData;
          console.log("Found candidate:", {
            id: p.id,
            name: adv.localName,
            rssi: p.rssi,
            serviceUuids: adv.serviceUuids,
            mfgDataHex: md ? hex(md) : "(none)",
          });
        }

        noble.stopScanning();
        let disconnectedEarly = false;
        p.once("disconnect", () => {
          if (!resolved) {
            disconnectedEarly = true;
            reject(new Error("Disconnected before service discovery"));
          }
        });

        await p.connectAsync();
        if (disconnectedEarly) return; // guard

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
        if (!tx || !rx)
          throw new Error(
            "TX/RX characteristics not found (no NUS on this device)"
          );

        // Enable notifications & settle before first write to avoid CoreBluetooth race
        await rx.subscribeAsync();
        await sleep(250);

        resolved = true;
        resolve({
          tx,
          rx,
          periph: p,
          name: adv.localName || p.id || "unknown",
        });
      } catch (e: any) {
        if (!resolved) reject(e);
      }
    };

    noble.on("discover", onDiscover);

    (async () => {
      await noble.startScanningAsync([], true); // scan all adverts; duplicates allowed
      while (!resolved && Date.now() < deadline) await sleep(200);
      noble.removeListener("discover", onDiscover);
      await noble.stopScanningAsync().catch(() => {});
      if (!resolved) reject(new Error("Scan timeout: no matching device"));
    })().catch(reject);
  });
}

// Send frame and wait for matching CMD reply (handles 0x10 Command Error)
async function sendAndWait(
  tx: any,
  rx: any,
  frame: Uint8Array,
  expectCmd: number,
  timeoutMs = 10000,
  verbose = false
): Promise<DecodedFrame> {
  return new Promise<DecodedFrame>(async (resolve, reject) => {
    const asm = new Reassembler();

    const onData = (chunk: Buffer) => {
      const frames = asm.push(new Uint8Array(chunk));
      for (const f of frames) {
        if (verbose) {
          console.log(
            `RX cmd=0x${f.cmd.toString(16)} key=0x${f.key.toString(
              16
            )} rand=0x${f.rand.toString(16)} crcOk=${f.crcOk}`
          );
          console.log("RX data (plain):", hex(f.dataPlain));
        }
        if (f.cmd === 0x10) {
          // Command Error Notification
          const code = f.dataPlain[0] ?? -1;
          const msg =
            code === 1
              ? "CRC verification failed"
              : code === 2
              ? "Communication KEY not obtained (handshake missing)"
              : code === 3
              ? "Invalid communication KEY (wrong header key?)"
              : `Device error code ${code}`;
          clear();
          return reject(new Error(`Device 0x10 error: ${msg}`));
        }
        if (f.cmd === expectCmd) {
          clear();
          return resolve(f);
        }
      }
    };
    const to = setTimeout(() => {
      clear();
      reject(new Error("Timeout waiting for response"));
    }, timeoutMs);
    function clear() {
      try {
        rx.removeListener("data", onData);
      } catch {}
      clearTimeout(to);
    }

    rx.on("data", onData);
    await writeFrame(tx, frame);
  });
}

// High-level protocol ops
async function cmdHandshake(
  tx: any,
  rx: any,
  deviceKey: string,
  verbose = false
): Promise<number> {
  const payload = asciiBytes(deviceKey);
  if (payload.length !== 8)
    throw new Error("Device KEY must be exactly 8 ASCII bytes");

  const attempt = async () => {
    const frame = buildFrame(0x01, payload, /*header KEY*/ 0x00, verbose);
    const rep = await sendAndWait(tx, rx, frame, 0x01, 10000, verbose);
    if (!rep.crcOk) throw new Error("CRC error in 0x01 reply");
    if (rep.dataPlain.length < 2) throw new Error("Bad 0x01 reply payload");
    const status = rep.dataPlain[0];
    const sessionKey = rep.dataPlain[1] & 0xff;
    if (status !== 1)
      throw new Error("Device KEY verification failed (status!=1)");
    return sessionKey;
  };

  try {
    return await attempt();
  } catch (e) {
    if (verbose) console.warn("Handshake retry:", (e as Error).message);
    await sleep(200);
    return await attempt();
  }
}

async function cmdQueryInfo(tx: any, rx: any, sk: number, verbose = false) {
  const frame = buildFrame(0x31, Uint8Array.from([0x01]), sk, verbose);
  const rep = await sendAndWait(tx, rx, frame, 0x31, 8000, verbose);
  if (!rep.crcOk) throw new Error("CRC error in 0x31 reply");
  console.log("IoT info (0x31):", hex(rep.dataPlain));
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
  // [0]=0x01, [1..4]=userId BE, [5..8]=timestamp BE, [9]=flags
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
  const rep = await sendAndWait(tx, rx, frame, 0x05, 10000, verbose);
  if (!rep.crcOk) throw new Error("CRC error in 0x05 reply");

  // Required ACK: DATA=0x02, no response expected
  const ack = buildFrame(0x05, Uint8Array.from([0x02]), sk, verbose);
  await writeFrame(tx, ack);
  console.log("Unlock sent and ACKed.");
}

async function cmdLock(tx: any, rx: any, sk: number, verbose = false) {
  const frame = buildFrame(0x15, Uint8Array.from([0x01]), sk, verbose);
  const rep = await sendAndWait(tx, rx, frame, 0x15, 10000, verbose);
  if (!rep.crcOk) throw new Error("CRC error in 0x15 reply");

  const ack = buildFrame(0x15, Uint8Array.from([0x02]), sk, verbose);
  await writeFrame(tx, ack);
  console.log("Lock sent and ACKed.");
}

// CLI
type Args = {
  id?: string; // CoreBluetooth id from scan
  name?: string; // substring of localName
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

// Main
(async () => {
  const args = parseArgs();
  const id = args.id;
  const name = args.name;
  const deviceKey = (args.deviceKey || DEFAULT_DEVICE_KEY) as string;
  const action = (args.action || "query") as Args["action"];
  const verbose = !!args.verbose;

  if (process.platform === "darwin" && (args as any).mac) {
    console.warn(
      "Note: macOS doesn’t expose BLE MAC addresses. Use --name=... or --id=..."
    );
  }

  console.log("Scanning for Omni scooter…", {
    id: id ?? "(any)",
    name: name ?? "(any)",
  });
  const {
    tx,
    rx,
    periph,
    name: foundName,
  } = await connectNUS({ id, nameContains: name, scanMs: 25000, verbose });
  console.log(`Connected to: ${foundName}`);

  // tiny extra settle to be safe (connectNUS already waited 250ms post-subscribe)
  await sleep(100);

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
  await periph.disconnectAsync().catch(() => {});
  process.exit(0);
})().catch((err) => {
  console.error("ERROR:", err?.message || err);
  process.exit(1);
});
