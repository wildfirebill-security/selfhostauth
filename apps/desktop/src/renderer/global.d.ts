import { DesktopApi } from "../main/preload.js";

declare global {
  interface Window {
    desktop: DesktopApi;
  }
}

export {};