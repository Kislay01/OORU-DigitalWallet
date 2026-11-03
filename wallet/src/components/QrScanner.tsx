import jsQR from "jsqr";
import { CameraOff } from "lucide-react";
import { useEffect, useRef, useState } from "react";

/** Reads QR codes from the camera. Needs HTTPS or localhost. */
export function QrScanner({ onResult }: { onResult: (text: string) => void }) {
  const video = useRef<HTMLVideoElement>(null);
  const canvas = useRef<HTMLCanvasElement>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let stream: MediaStream | null = null;
    let raf = 0;
    let done = false;
    (async () => {
      if (!navigator.mediaDevices?.getUserMedia) {
        setError("Camera isn't available here (it needs HTTPS or localhost). Paste the link instead.");
        return;
      }
      try {
        stream = await navigator.mediaDevices.getUserMedia({ video: { facingMode: "environment" } });
      } catch {
        setError("Camera permission was denied. Paste the link instead.");
        return;
      }
      const v = video.current!;
      v.srcObject = stream;
      await v.play().catch(() => {});
      const tick = () => {
        if (done) return;
        const c = canvas.current;
        if (c && v.readyState === v.HAVE_ENOUGH_DATA) {
          c.width = v.videoWidth; c.height = v.videoHeight;
          const ctx = c.getContext("2d", { willReadFrequently: true })!;
          ctx.drawImage(v, 0, 0, c.width, c.height);
          const img = ctx.getImageData(0, 0, c.width, c.height);
          const code = jsQR(img.data, img.width, img.height, { inversionAttempts: "dontInvert" });
          if (code?.data) { done = true; onResult(code.data); return; }
        }
        raf = requestAnimationFrame(tick);
      };
      raf = requestAnimationFrame(tick);
    })();
    return () => { done = true; cancelAnimationFrame(raf); stream?.getTracks().forEach((t) => t.stop()); };
  }, [onResult]);

  if (error) {
    return (
      <div className="flex aspect-square w-full flex-col items-center justify-center gap-2 rounded-2xl border border-dashed border-slate-300 bg-slate-100 p-6 text-center text-sm text-slate-500">
        <CameraOff size={28} /> {error}
      </div>
    );
  }
  return (
    <div className="relative aspect-square w-full overflow-hidden rounded-2xl bg-black">
      <video ref={video} className="h-full w-full object-cover" muted playsInline />
      <div className="pointer-events-none absolute inset-8 rounded-xl border-2 border-white/80 shadow-[0_0_0_9999px_rgba(0,0,0,0.35)]" />
      <canvas ref={canvas} className="hidden" />
    </div>
  );
}
