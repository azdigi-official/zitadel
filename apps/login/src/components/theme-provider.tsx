"use client";
import { ThemeProvider as ThemeP } from "next-themes";
import { ReactNode } from "react";

export function ThemeProvider({ children }: { children: ReactNode }) {
  return (
    <ThemeP
      attribute="class"
      defaultTheme="light"
      // AZDIGI: light only like the AntiWHMCS sign-in screens (#48); branding themeMode is THEME_MODE_LIGHT too
      forcedTheme="light"
      storageKey="cp-theme"
      value={{ dark: "dark" }}
    >
      {children}
    </ThemeP>
  );
}
