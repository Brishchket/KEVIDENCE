import type { Metadata } from "next";
import { Inter } from "next/font/google";
import "./globals.css";
import Navbar from "@/components/Navbar";
import { ThemeProvider } from "@/components/ThemeProvider";

const inter = Inter({
  subsets: ["latin"],
  variable: "--font-inter",
  display: "swap",
});

export const metadata: Metadata = {
  title: "KEVIDENCE — Vulnerability Intelligence & Risk Prioritization",
  description: "Evidence-grounded vulnerability prioritization and audience-specific risk narrative engine.",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" className={inter.variable} suppressHydrationWarning>
      <head>
        <script
          dangerouslySetInnerHTML={{
            __html: `(function(){try{var t=localStorage.getItem('kevidence_theme');if(t==='dark'||(!t&&window.matchMedia('(prefers-color-scheme: dark)').matches&&false)){document.documentElement.setAttribute('data-theme','dark');document.documentElement.classList.add('dark');}else{document.documentElement.setAttribute('data-theme','light');document.documentElement.classList.remove('dark');}}catch(e){}})();`,
          }}
        />
      </head>
      <body className="antialiased bg-[#F8F9FA] dark:bg-[#0B1120] text-gray-900 dark:text-[#F8FAFC] min-h-screen flex flex-col font-sans transition-colors duration-150">
        <ThemeProvider>
          <Navbar />
          <main className="max-w-[1600px] mx-auto px-4 sm:px-6 lg:px-8 py-8 w-full flex-grow">
            {children}
          </main>
          <footer className="border-t border-gray-200/80 dark:border-[#273449] bg-white/80 dark:bg-[#111827]/90 py-6 mt-12 text-center text-xs text-gray-500 dark:text-slate-400 transition-colors">
            <div className="max-w-[1600px] mx-auto px-4 flex flex-col sm:flex-row items-center justify-between gap-2">
              <span className="font-semibold text-gray-700 dark:text-slate-300">
                KEVIDENCE &bull; Evidence-Grounded Vulnerability Risk Engine
              </span>
              <span className="text-gray-500 dark:text-slate-400">
                DATA &rarr; EVIDENCE &rarr; PRIORITY &rarr; EXPLANATION &rarr; VERIFICATION
              </span>
            </div>
          </footer>
        </ThemeProvider>
      </body>
    </html>
  );
}
