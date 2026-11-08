import jsQR from "jsqr";

/** Longest side to try first, then smaller sizes (dense QR codes in big screenshots read better downscaled). */
const SIZES = [2000, 1200, 800];

async function loadImage(file: Blob): Promise<CanvasImageSource & { width: number; height: number }> {
  if ("createImageBitmap" in window) {
    try { return await createImageBitmap(file); } catch { /* fall back below */ }
  }
  const url = URL.createObjectURL(file);
  try {
    const img = new Image();
    img.src = url;
    await img.decode();
    return img;
  } finally {
    URL.revokeObjectURL(url);
  }
}

/** Read a QR code from an image the user picked, pasted or dropped. */
export async function decodeQrFromImage(file: Blob): Promise<string> {
  if (!file.type.startsWith("image/")) throw new Error("That file isn't an image.");
  let img;
  try { img = await loadImage(file); } catch { throw new Error("Couldn't open that image."); }

  const canvas = document.createElement("canvas");
  const ctx = canvas.getContext("2d", { willReadFrequently: true })!;
  const longest = Math.max(img.width, img.height);
  for (const size of SIZES) {
    const scale = Math.min(1, size / longest);
    canvas.width = Math.max(1, Math.round(img.width * scale));
    canvas.height = Math.max(1, Math.round(img.height * scale));
    ctx.fillStyle = "#fff";
    ctx.fillRect(0, 0, canvas.width, canvas.height); // transparent PNGs → white background
    ctx.drawImage(img, 0, 0, canvas.width, canvas.height);
    const data = ctx.getImageData(0, 0, canvas.width, canvas.height);
    const code = jsQR(data.data, data.width, data.height, { inversionAttempts: "attemptBoth" });
    if (code?.data) return code.data;
  }
  throw new Error("No QR code found in that image. Try a clearer or tighter crop of the QR.");
}

/** First image in a paste or drop, if any. */
export function imageFrom(items: DataTransferItemList | null | undefined, files?: FileList | null): File | null {
  for (const f of Array.from(files || [])) if (f.type.startsWith("image/")) return f;
  for (const it of Array.from(items || [])) {
    if (it.kind === "file" && it.type.startsWith("image/")) {
      const f = it.getAsFile();
      if (f) return f;
    }
  }
  return null;
}
