import type { ReactNode } from "react";

export const metadata = {
  title: "ClearSight Scanner",
  description: "Detect steganographic Unicode payloads in text",
};

export default function RootLayout({ children }: { children: ReactNode }) {
  return (
    <html lang="en">
      <body style={{ fontFamily: "system-ui, sans-serif", margin: 0, padding: 0, backgroundColor: "#f4f4f5" }}>
        {children}
      </body>
    </html>
  );
}