import type { Metadata } from "next";
import "./globals.css";
import { Providers } from "./providers";

export const metadata: Metadata = { title: "Vigil SOC", description: "AI-native multi-cloud security operations" };

// Applies the saved/OS theme before paint to avoid a flash.
const themeScript = `try{var t=localStorage.getItem("vigil-theme");if(t==="dark"||(!t&&matchMedia("(prefers-color-scheme: dark)").matches))document.documentElement.classList.add("dark")}catch(e){}`;

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" suppressHydrationWarning>
      <head><script dangerouslySetInnerHTML={{ __html: themeScript }} /></head>
      <body className="antialiased text-[13px]"><Providers>{children}</Providers></body>
    </html>
  );
}
